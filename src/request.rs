use std::fmt;
use std::io::Read;

use url::{form_urlencoded, Url};

use crate::body::Payload;
use crate::error::ErrorKind;
use crate::header::{self, Header};
use crate::unit::{self, Unit};
use crate::Response;
use crate::{agent::Agent, error::Error};

#[cfg(feature = "json")]
use super::SerdeValue;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Clone)]
struct ParsedUrl {
    /// The original plain string when the Request is instantiated using a `String`.
    /// None if the Request is instantiated with a `Url`.
    plain_str: Option<String>,
    /// Parse result, regardless of whether `plain_str` has a value or not.
    parse_result: std::result::Result<Url, url::ParseError>,
    /// This is necessary because Url::query_pairs() gives us Cow<String>
    /// and Cow is not something we want to expose in our API.
    query_params: Vec<(String, String)>,
}

impl ParsedUrl {
    fn as_str(&self) -> &str {
        if let Some(s) = &self.plain_str {
            // prefer plain_str since if this is set, it is what the user
            // passed into the request.
            s
        } else {
            match &self.parse_result {
                // fallback on Url
                Ok(u) => u.as_str(),
                // This cannot happen since either we constructed the ParsedUrl
                // from String, in which case we use that above, or we construct
                // from Url, in which case we have Ok(url) in parse_result.
                Err(_) => unreachable!(),
            }
        }
    }

    /// Turn query_params `Cow<String>` to proper `String`
    fn extract_query_params(mut self) -> Self {
        if let Ok(url) = &self.parse_result {
            for (k, v) in url.query_pairs() {
                self.query_params.push((k.to_string(), v.to_string()));
            }
        }
        self
    }
}

impl fmt::Display for ParsedUrl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl From<String> for ParsedUrl {
    fn from(s: String) -> Self {
        let parse_result = s.parse();
        ParsedUrl {
            plain_str: Some(s),
            parse_result,
            query_params: vec![],
        }
        .extract_query_params()
    }
}

impl From<Url> for ParsedUrl {
    fn from(url: Url) -> Self {
        ParsedUrl {
            plain_str: None,
            parse_result: Ok(url),
            query_params: vec![],
        }
        .extract_query_params()
    }
}

/// Request instances are builders that creates a request.
///
/// ```
/// # fn main() -> Result<(), ureq::Error> {
/// # ureq::is_test(true);
/// let response = ureq::get("http://example.com/form")
///     .query("foo", "bar baz")  // add ?foo=bar+baz
///     .call()?;                 // run the request
/// # Ok(())
/// # }
/// ```
#[derive(Clone)]
pub struct Request {
    agent: Agent,
    method: String,
    parsed_url: ParsedUrl,
    error_on_non_2xx: bool,
    headers: Vec<Header>,
    query_params: Vec<(String, String)>,
}

impl fmt::Debug for Request {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "Request({} {} {:?}, {:?})",
            self.method, self.parsed_url, self.query_params, self.headers
        )
    }
}

impl Request {
    pub(crate) fn new(agent: Agent, method: String, url: String) -> Request {
        Request {
            agent,
            method,
            parsed_url: url.into(),
            headers: vec![],
            error_on_non_2xx: true,
            query_params: vec![],
        }
    }

    pub(crate) fn with_url(agent: Agent, method: String, url: Url) -> Request {
        Request {
            agent,
            method,
            parsed_url: url.into(),
            headers: vec![],
            error_on_non_2xx: true,
            query_params: vec![],
        }
    }

    /// Sends the request with no body and blocks the caller until done.
    ///
    /// Use this with GET, HEAD, OPTIONS or TRACE. It sends neither
    /// Content-Length nor Transfer-Encoding.
    ///
    /// ```
    /// # fn main() -> Result<(), ureq::Error> {
    /// # ureq::is_test(true);
    /// let resp = ureq::get("http://example.com/")
    ///     .call()?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn call(self) -> Result<Response> {
        self.do_call(Payload::Empty)
    }

    fn do_call(self, payload: Payload) -> Result<Response> {
        for h in &self.headers {
            h.validate()?;
        }
        let mut url = self.parsed_url.parse_result.map_err(|e| {
            ErrorKind::InvalidUrl
                .msg(&format!("failed to parse URL: {:?}", e))
                .src(e)
        })?;
        for (name, value) in self.query_params {
            url.query_pairs_mut().append_pair(&name, &value);
        }
        let reader = payload.into_read();
        let unit = Unit::new(&self.agent, &self.method, &url, &self.headers, &reader);
        let response = unit::connect(unit, true, reader).map_err(|e| e.url(url))?;

        if response.status() >= 400 {
            Err(Error::Status(response.status(), response))
        } else {
            Ok(response)
        }
    }

    /// Send data a json value.
    ///
    /// Requires feature `ureq = { version = "*", features = ["json"] }`
    ///
    /// The `Content-Length` header is implicitly set to the length of the serialized value.
    ///
    /// ```
    /// # fn main() -> Result<(), ureq::Error> {
    /// # ureq::is_test(true);
    /// let resp = ureq::post("http://httpbin.org/post")
    ///     .send_json(ureq::json!({
    ///       "name": "martin",
    ///       "rust": true,
    ///     }))?;
    /// # Ok(())
    /// # }
    /// ```
    #[cfg(feature = "json")]
    pub fn send_json(mut self, data: SerdeValue) -> Result<Response> {
        if self.header("Content-Type").is_none() {
            self = self.set("Content-Type", "application/json");
        }
        self.do_call(Payload::JSON(data))
    }

    /// Send data as bytes.
    ///
    /// The `Content-Length` header is implicitly set to the length of the serialized value.
    ///
    /// ```
    /// # fn main() -> Result<(), ureq::Error> {
    /// # ureq::is_test(true);
    /// let resp = ureq::put("http://httpbin.org/put")
    ///     .send_bytes(&[0; 1000])?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn send_bytes(self, data: &[u8]) -> Result<Response> {
        self.do_call(Payload::Bytes(data))
    }

    /// Send data as a string.
    ///
    /// The `Content-Length` header is implicitly set to the length of the serialized value.
    /// Defaults to `utf-8`
    ///
    /// ## Charset support
    ///
    /// Requires feature `ureq = { version = "*", features = ["charset"] }`
    ///
    /// If a `Content-Type` header is present and it contains a charset specification, we
    /// attempt to encode the string using that character set. If it fails, we fall back
    /// on utf-8.
    ///
    /// ```
    /// // this example requires features = ["charset"]
    ///
    /// # fn main() -> Result<(), ureq::Error> {
    /// # ureq::is_test(true);
    /// let resp = ureq::post("http://httpbin.org/post")
    ///     .set("Content-Type", "text/plain; charset=iso-8859-1")
    ///     .send_string("Hällo Wörld!")?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn send_string(self, data: &str) -> Result<Response> {
        let charset =
            crate::response::charset_from_content_type(self.header("content-type")).to_string();
        self.do_call(Payload::Text(data, charset))
    }

    /// Send a sequence of (key, value) pairs as form-urlencoded data.
    ///
    /// The `Content-Type` header is implicitly set to application/x-www-form-urlencoded.
    /// The `Content-Length` header is implicitly set to the length of the serialized value.
    ///
    /// ```
    /// # fn main() -> Result<(), ureq::Error> {
    /// # ureq::is_test(true);
    /// let resp = ureq::post("http://httpbin.org/post")
    ///     .send_form(&[
    ///       ("foo", "bar"),
    ///       ("foo2", "bar2"),
    ///     ])?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn send_form(mut self, data: &[(&str, &str)]) -> Result<Response> {
        if self.header("Content-Type").is_none() {
            self = self.set("Content-Type", "application/x-www-form-urlencoded");
        }
        let encoded = form_urlencoded::Serializer::new(String::new())
            .extend_pairs(data)
            .finish();
        self.do_call(Payload::Bytes(&encoded.into_bytes()))
    }

    /// Send data from a reader.
    ///
    /// If no Content-Length and Transfer-Encoding header has been set, it uses the [chunked transfer encoding](https://tools.ietf.org/html/rfc7230#section-4.1).
    ///
    /// The caller may set the Content-Length header to the expected byte size of the reader if is
    /// known.
    ///
    /// The input from the reader is buffered into chunks of size 16,384, the max size of a TLS fragment.
    ///
    /// ```
    /// use std::io::Cursor;
    /// # fn main() -> Result<(), ureq::Error> {
    /// # ureq::is_test(true);
    /// let read = Cursor::new(vec![0x20; 100]);
    /// let resp = ureq::post("http://httpbin.org/post")
    ///     .send(read)?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn send(self, reader: impl Read) -> Result<Response> {
        self.do_call(Payload::Reader(Box::new(reader)))
    }

    /// Set a header field.
    ///
    /// ```
    /// # fn main() -> Result<(), ureq::Error> {
    /// # ureq::is_test(true);
    /// let resp = ureq::get("http://httpbin.org/bytes/1000")
    ///     .set("Accept", "text/plain")
    ///     .set("Range", "bytes=500-999")
    ///     .call()?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn set(mut self, header: &str, value: &str) -> Self {
        header::add_header(&mut self.headers, Header::new(header, value));
        self
    }

    /// Returns the value for a set header.
    ///
    /// ```
    /// let req = ureq::get("/my_page")
    ///     .set("X-API-Key", "foobar");
    /// assert_eq!("foobar", req.header("x-api-Key").unwrap());
    /// ```
    pub fn header(&self, name: &str) -> Option<&str> {
        header::get_header(&self.headers, name)
    }

    /// A list of the set header names in this request. Lowercased to be uniform.
    ///
    /// ```
    /// let req = ureq::get("/my_page")
    ///     .set("X-API-Key", "foobar")
    ///     .set("Content-Type", "application/json");
    /// assert_eq!(req.header_names(), vec!["x-api-key", "content-type"]);
    /// ```
    pub fn header_names(&self) -> Vec<String> {
        self.headers
            .iter()
            .map(|h| h.name().to_ascii_lowercase())
            .collect()
    }

    /// Tells if the header has been set.
    ///
    /// ```
    /// let req = ureq::get("/my_page")
    ///     .set("X-API-Key", "foobar");
    /// assert_eq!(true, req.has("x-api-Key"));
    /// ```
    pub fn has(&self, name: &str) -> bool {
        header::has_header(&self.headers, name)
    }

    /// All headers corresponding values for the give name, or empty vector.
    ///
    /// ```
    /// let req = ureq::get("/my_page")
    ///     .set("X-Forwarded-For", "1.2.3.4")
    ///     .set("X-Forwarded-For", "2.3.4.5");
    ///
    /// assert_eq!(req.all("x-forwarded-for"), vec![
    ///     "1.2.3.4",
    ///     "2.3.4.5",
    /// ]);
    /// ```
    pub fn all(&self, name: &str) -> Vec<&str> {
        header::get_all_headers(&self.headers, name)
    }

    /// Set a query parameter.
    ///
    /// For example, to set `?format=json&dest=/login`
    ///
    /// ```
    /// # fn main() -> Result<(), ureq::Error> {
    /// # ureq::is_test(true);
    /// let resp = ureq::get("http://httpbin.org/response-headers")
    ///     .query("format", "json")
    ///     .query("dest", "/login")
    ///     .call()?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn query(mut self, param: &str, value: &str) -> Self {
        self.query_params
            .push((param.to_string(), value.to_string()));
        self
    }

    /// Returns the value of the request method. Something like `GET`, `POST`, `PUT` etc.
    ///
    /// ```
    /// let req = ureq::put("http://httpbin.org/put");
    ///
    /// assert_eq!(req.method(), "PUT");
    /// ```
    pub fn method(&self) -> &str {
        &self.method
    }

    /// Returns the url of the request.
    ///
    /// ```
    /// let req = ureq::put("http://httpbin.org/put");
    ///
    /// assert_eq!(req.url(), "http://httpbin.org/put");
    /// ```
    pub fn url(&self) -> &str {
        self.parsed_url.as_str()
    }

    /// Helper to get all query parameters both from Url and Request::query
    fn all_query_params(&self) -> impl Iterator<Item = (&str, &str)> {
        self.parsed_url
            // first add query parameters from the url
            .query_params
            .iter()
            // then additional query parameters from Request
            .chain(self.query_params.iter())
            .map(|(k, v)| (k.as_str(), v.as_str()))
    }

    /// Returns all the query parameter names.
    ///
    /// ```
    /// // query parameter provided in url
    /// let mut req = ureq::get("http://httpbin.org/get?foo=bar")
    ///     // query parameters added on Request
    ///     .query("foo", "again")
    ///     .query("baz", "qux");
    ///
    /// assert_eq!(req.query_params(), vec![
    ///    "foo",
    ///    "baz",
    /// ]);
    /// ```
    pub fn query_params(&self) -> Vec<&str> {
        let mut ret: Vec<&str> = self.all_query_params().map(|(param, _)| param).collect();
        ret.dedup();
        ret
    }

    /// Returns a query value.
    ///
    /// ```
    /// // query parameter provided in url
    /// let mut req = ureq::get("http://httpbin.org/get?foo=bar")
    ///     // query parameter added on Request
    ///     .query("baz", "qux");
    ///
    /// assert_eq!(req.query_value("foo"), Some("bar"));
    /// assert_eq!(req.query_value("baz"), Some("qux"));
    /// assert_eq!(req.query_value("corge"), None);
    /// ```
    pub fn query_value(&self, param: &str) -> Option<&str> {
        self.all_query_params()
            .find(|(k, _)| *k == param)
            .map(|(_, v)| v)
    }

    /// Returns all values for a query parameter. This is useful when the same query parameter is
    /// repeated many times.
    ///
    /// ```
    /// // (repeated) query parameter provided in url
    /// let mut req = ureq::get("http://httpbin.org/get?foo=bar&foo=baz")
    ///     // (repeated) query parameter added on Request
    ///     .query("foo", "qux");
    ///
    /// assert_eq!(req.query_values("foo"), vec![
    ///    "bar",
    ///    "baz",
    ///    "qux",
    /// ]);
    /// ```
    pub fn query_values(&self, param: &str) -> Vec<&str> {
        self.all_query_params()
            .filter(|(k, _)| *k == param)
            .map(|(_, v)| v)
            .collect()
    }
}

#[test]
fn request_implements_send_and_sync() {
    let _request: Box<dyn Send> = Box::new(Request::new(
        Agent::new(),
        "GET".to_string(),
        "https://example.com/".to_string(),
    ));
    let _request: Box<dyn Sync> = Box::new(Request::new(
        Agent::new(),
        "GET".to_string(),
        "https://example.com/".to_string(),
    ));
}

#[test]
fn send_byte_slice() {
    let bytes = vec![1, 2, 3];
    crate::agent()
        .post("http://example.com")
        .send(&bytes[1..2])
        .ok();
}
