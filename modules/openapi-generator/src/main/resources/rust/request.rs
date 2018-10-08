use std::borrow::Cow;
use std::collections::HashMap;

use super::{configuration, Error};
use futures;
use futures::{Future, Stream};
use hyper;
use hyper::header::USER_AGENT;
use hyper::header::AUTHORIZATION;
use base64::encode;
use serde;
use serde_json;

const MIME_APPLICATION_WWW_FORM_URLENCODED: &'static str = "application/x-www-form-urlencoded";
const MIME_APPLICATION_JSON: &'static str = "application/json";

pub(crate) struct ApiKey {
    pub in_header: bool,
    pub in_query: bool,
    pub param_name: String,
}

impl ApiKey {
    fn key(&self, prefix: &Option<String>, key: &str) -> String {
        match prefix {
            None => key.to_owned(),
            Some(ref prefix) => format!("{} {}", prefix, key),
        }
    }
}

pub(crate) enum Auth {
    None,
    ApiKey(ApiKey),
    Basic,
    Oauth,
}

pub(crate) struct Request {
    auth: Auth,
    method: hyper::Method,
    path: String,
    query_params: HashMap<String, String>,
    no_return_type: bool,
    path_params: HashMap<String, String>,
    form_params: HashMap<String, String>,
    header_params: HashMap<String, String>,
    // TODO: multiple body params are possible technically, but not supported here.
    serialized_body: Option<String>,
}

impl Request {
    pub fn new(method: hyper::Method, path: String) -> Self {
        Request {
            auth: Auth::None,
            method: method,
            path: path,
            query_params: HashMap::new(),
            path_params: HashMap::new(),
            form_params: HashMap::new(),
            header_params: HashMap::new(),
            serialized_body: None,
            no_return_type: false,
        }
    }

    pub fn with_body_param<T: serde::Serialize>(mut self, param: T) -> Self {
        self.serialized_body = Some(serde_json::to_string(&param).unwrap());
        self
    }

    pub fn with_header_param(mut self, basename: String, param: String) -> Self {
        self.header_params.insert(basename, param);
        self
    }

    pub fn with_query_param(mut self, basename: String, param: String) -> Self {
        self.query_params.insert(basename, param);
        self
    }

    pub fn with_path_param(mut self, basename: String, param: String) -> Self {
        self.path_params.insert(basename, param);
        self
    }

    pub fn with_form_param(mut self, basename: String, param: String) -> Self {
        self.form_params.insert(basename, param);
        self
    }

    pub fn returns_nothing(mut self) -> Self {
        self.no_return_type = true;
        self
    }

    pub fn with_auth(mut self, auth: Auth) -> Self {
        self.auth = auth;
        self
    }

    pub fn execute<'a, C, U>(
        self,
        conf: &configuration::Configuration<C>,
    ) -> Box<Future<Item = U, Error = Error<serde_json::Value>> + 'a + Send>
    where
        C: hyper::client::connect::Connect + 'static,
        U: Sized + 'a,
        for<'de> U: serde::Deserialize<'de> + Send,
    {
        let mut query_string = ::url::form_urlencoded::Serializer::new("".to_owned());
        // raw_headers is for headers we don't know the proper type of (e.g. custom api key
        // headers); headers is for ones we do know the type of.
        let mut raw_headers: HashMap<String, String> = HashMap::new();
        let mut headers: hyper::header::HeaderMap = hyper::header::HeaderMap::new();

        let mut path = self.path;
        for (k, v) in self.path_params {
            // replace {id} with the value of the id path param
            path = path.replace(&format!("{{{}}}", k), &v);
        }

        for (k, v) in self.header_params {
            raw_headers.insert(k, v);
        }

        for (key, val) in self.query_params {
            query_string.append_pair(&key, &val);
        }

        match self.auth {
            Auth::ApiKey(apikey) => {
                if let Some(ref key) = conf.api_key {
                    let val = apikey.key(&key.prefix, &key.key);
                    if apikey.in_query {
                        query_string.append_pair(&apikey.param_name, &val);
                    }
                    if apikey.in_header {
                        raw_headers.insert(apikey.param_name, val);
                    }
                }
            }
            Auth::Basic => {
                if let Some(ref auth_conf) = conf.basic_auth {
                    let ref username = auth_conf.0;

                    let user_password = if let Some(ref password) = auth_conf.1 {
                        format!("{}:{}", username, password)
                    } else {
                        username.to_owned()
                    };

                    let raw_header_value = format!("Basic {}", encode(&user_password));
                    let basic_auth = hyper::header::HeaderValue::from_str(&raw_header_value).unwrap();
                    headers.insert(hyper::header::AUTHORIZATION, basic_auth);
                }
            }
            Auth::Oauth => {
                if let Some(ref token) = conf.oauth_access_token {
                    let raw_header_value = format!("Bearer {}", token);
                    let bearer_auth = hyper::header::HeaderValue::from_str(&raw_header_value).unwrap();
                    headers.insert(hyper::header::AUTHORIZATION, bearer_auth);
                }
            }
            Auth::None => {}
        }

        let mut uri_str = format!("{}{}", conf.base_path, path);

        let query_string_str = query_string.finish();
        if query_string_str != "" {
            uri_str += "?";
            uri_str += &query_string_str;
        }
        let uri: hyper::Uri = match uri_str.parse() {
            Err(e) => {
                return Box::new(futures::future::err(Error::UriError(e)));
            }
            Ok(u) => u,
        };

        let mut builder = hyper::Request::builder();
        let req_builder = builder
            .uri(uri)
            .method(self.method);

        {
            if let Some(ref user_agent) = conf.user_agent {
                req_builder.header(USER_AGENT, user_agent.clone());
            }

            for (name_opt, value) in headers {
                if let Some(ref name) = name_opt {
                    req_builder.header(name, value.clone());
                }
            }

            for (name, value) in raw_headers {
                req_builder.header(name.as_str(), value.as_str());
            }
        }
        
        let req = if self.form_params.len() > 0 {
            let mut enc = ::url::form_urlencoded::Serializer::new("".to_owned());
            for (k, v) in self.form_params {
                enc.append_pair(&k, &v);
            }

            req_builder
                .header(hyper::header::CONTENT_TYPE, MIME_APPLICATION_WWW_FORM_URLENCODED)
                .body(hyper::Body::from(enc.finish())).unwrap()

        } else if let Some(body) = self.serialized_body {
            req_builder
                .header(hyper::header::CONTENT_TYPE, MIME_APPLICATION_JSON)
                .header(hyper::header::CONTENT_LENGTH, body.len() as u64)
                .body(hyper::Body::from(body)).unwrap()

        } else {
            req_builder
                .header(hyper::header::CONTENT_LENGTH, 0 as u64)
                .body(hyper::Body::default()).unwrap()
        };

        let no_ret_type = self.no_return_type;
        let res = conf.client
                .request(req)
                .map_err(|e| Error::from(e))
                .and_then(|resp| {
                    let (head, body) = resp.into_parts();
                    body.concat2()
                        .and_then(move |body| Ok((head.status, body)))
                        .map_err(|e| Error::from(e))
                })
                .and_then(|(status, body)| {
                    if status.is_success() {
                        Ok(body)
                    } else {
                        Err(Error::from((status, &*body)))
                    }
                });
        Box::new(
            res
                .and_then(move |body| {
                    let parsed: Result<U, _> = if no_ret_type {
                        // This is a hack; if there's no_ret_type, U is (), but serde_json gives an
                        // error when deserializing "" into (), so deserialize 'null' into it
                        // instead.
                        // An alternate option would be to require U: Default, and then return
                        // U::default() here instead since () implements that, but then we'd
                        // need to impl default for all models.
                        serde_json::from_str("null")
                    } else {
                        serde_json::from_slice(&body)
                    };
                    parsed.map_err(|e| Error::from(e))
                })
        )
    }
}
