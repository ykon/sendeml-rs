/**
 * Copyright (c) Yuki Ono.
 * Licensed under the MIT License.
 */

use std::env;
use std::fs;
use std::fmt;
use std::io::BufReader;
use std::io::prelude::*;
use std::net::TcpStream;
use std::path::Path;
use std::process;
use std::thread;
use chrono::prelude::*;
use rand::{thread_rng, Rng};
use rand::distributions::Alphanumeric;
use rayon::prelude::*;
use serde_json::Value;

const CR: u8 = b'\r';
const LF: u8 = b'\n';
const CRLF: &str = "\r\n";
const VERSION: f64 = 1.1;

fn make_now_date_line() -> String {
    format!("Date: {}{}", Local::now().format("%a, %d %b %Y %H:%M:%S %z"), CRLF)
}

fn make_random_message_id_line() -> String {
    let length = 62;
    let rand_str: String = thread_rng()
        .sample_iter(&Alphanumeric)
        .take(length)
        .collect();
    format!("Message-ID: <{}>{}", rand_str, CRLF)
}

fn replace_message_id_line(file_buf: &[u8]) -> std::borrow::Cow<[u8]> {
    let re = regex::bytes::Regex::new(r"Message-ID:[\s\S]+?\r\n([^ \t]|$)").unwrap();
    re.replace(file_buf, format!("{}$1", make_random_message_id_line()).as_bytes())
}

fn replace_date_line(file_buf: &[u8]) -> std::borrow::Cow<[u8]> {
    let re = regex::bytes::Regex::new(r"Date:[\s\S]+?\r\n([^ \t]|$)").unwrap();
    re.replace(&file_buf, format!("{}$1", make_now_date_line()).as_bytes())
}

fn is_not_update(update_date: bool, update_message_id: bool) -> bool {
    !update_date && !update_message_id
}

fn find_empty_line(file_buf: &[u8]) -> Option<usize> {
    let re = regex::bytes::Regex::new(r"\r\n\r\n").unwrap();
    re.find(&file_buf).map(|m| m.start())
}

const EMPTY_LINE: [u8; 4] = [CR, LF, CR, LF];

fn combine_mail(header: &[u8], body: &[u8]) -> Vec<u8> {
    [header, &EMPTY_LINE, body].concat()
}

fn split_mail(file_buf: &[u8]) -> Option<(Vec<u8>, Vec<u8>)> {
    find_empty_line(file_buf).map(|idx| {
        let header = file_buf[0..idx].to_vec();
        let body = file_buf[(idx + EMPTY_LINE.len())..file_buf.len()].to_vec();
        (header, body)
    })
}

fn replace_header(header: &[u8], update_date: bool, update_message_id: bool) -> Vec<u8> {
    match (update_date, update_message_id) {
        (true, true) => replace_message_id_line(&replace_date_line(&header)).into_owned(),
        (true, false) => replace_date_line(header).into_owned(),
        (false, true) => replace_message_id_line(&header).into_owned(),
        (false, false) => header.to_owned()
    }
}

fn replace_mail(file_buf: &[u8], update_date: bool, update_message_id: bool) -> Vec<u8> {
    if is_not_update(update_date, update_message_id) {
        return file_buf.to_owned()
    }

    match split_mail(&file_buf) {
        Some((header, body)) => {
            let repl_header = replace_header(&header, update_date, update_message_id);
            combine_mail(&repl_header, &body)
        },
        None => {
            println!("error: Invalid mail: Disable updateDate, updateMessageId");
            file_buf.to_owned()
        }
    }
}

fn make_json_sample() -> String {
    let json = r#"{
    "smtpHost": "172.16.3.151",
    "smtpPort": 25,
    "fromAddress": "a001@ah62.example.jp",
    "toAddresses": [
        "a001@ah62.example.jp",
        "a002@ah62.example.jp",
        "a003@ah62.example.jp"
    ],
    "emlFiles": [
        "test1.eml",
        "test2.eml",
        "test3.eml"
    ],
    "updateDate": true,
    "updateMessageId": true,
    "useParallel": false
}"#;
    json.to_string()
}

fn print_usage() -> () {
    println!("Usage: {{self}} json_file ...");
    println!("---");

    println!("json_file sample:");
    println!("{}", make_json_sample())
}

fn print_version() {
    println!("SendEML / Version: {0:.1}", VERSION);
}

fn make_id_prefix(use_parallel: bool) -> String {
    return if use_parallel {
        format!("{:?}, ", thread::current().id())
    } else {
        "".to_string()
    }
}

struct Settings {
    smtp_host: String,
    smtp_port: u32,
    from_address: String,
    to_addresses: Vec<String>,
    eml_files: Vec<String>,
    update_date: bool,
    update_message_id: bool,
    use_parallel: bool
}

#[derive(Debug)]
enum SendEmlError {
    IoError(std::io::Error),
    JsonError(serde_json::Error),
    StrError(String)
}

impl fmt::Display for SendEmlError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match &*self {
            SendEmlError::IoError(e) => write!(f, "{}", e),
            SendEmlError::JsonError(e) => write!(f, "{}", e),
            SendEmlError::StrError(s) => write!(f, "{}", s)
        }
    }
}

type SendEmlResult<T> = Result<T, SendEmlError>;

impl From<serde_json::Error> for SendEmlError {
    fn from(e: serde_json::Error) -> Self {
        Self::JsonError(e)
    }
}

impl From<std::io::Error> for SendEmlError {
    fn from(e: std::io::Error) -> Self {
        Self::IoError(e)
    }
}

fn new_error(msg: &str) -> SendEmlError {
    SendEmlError::StrError(msg.to_owned())
}

fn get_settings_from_text(text: &str) -> SendEmlResult<Value> {
    serde_json::from_str(text).map_err(|e| SendEmlError::JsonError(e))
}

fn get_settings(json_file: &str) -> SendEmlResult<Value> {
    get_settings_from_text(&fs::read_to_string(json_file)?)
}

type ValuePred = for<'r> fn(&'r Value) -> bool;

fn check_json_value(json: &Value, name: &str, pred: ValuePred) -> SendEmlResult<()> {
    match json.get(name) {
        Some(v) if !pred(v) => {
            Err(new_error(&format!("{}: Invalid type: {}", name, v)))
        },
        _ => Ok(())
    }
}

fn check_json_array_value(json: &Value, name: &str, pred: ValuePred) -> SendEmlResult<()> {
    match json.get(name) {
        Some(v) => {
            if !v.is_array() {
                return Err(new_error(&format!("{}: Invalid type (array): {}", name, v)))
            }
            if let Some(elm) = v.as_array().unwrap().iter().find(|v| !pred(v)) {
                return Err(new_error(&format!("{}: Invalid type (element): {}", name, elm)))
            }
            Ok(())
        },
        _ => Ok(())
    }
}

fn check_settings(json: &Value) -> SendEmlResult<()> {
    let names = ["smtpHost", "smtpPort", "fromAddress", "toAddresses", "emlFiles"];
    if let Some(key) = names.iter().find(|n| json.get(n).is_none()) {
        return Err(new_error(&format!("{} key does not exist", key)))
    }

    check_json_value(json, "smtpHost", Value::is_string)?;
    check_json_value(json, "smtpPort", Value::is_number)?;
    check_json_value(json, "fromAddress", Value::is_string)?;
    check_json_array_value(json, "toAddresses", Value::is_string)?;
    check_json_array_value(json, "emlFiles", Value::is_string)?;
    check_json_value(json, "updateDate", Value::is_boolean)?;
    check_json_value(json, "updateMessageId", Value::is_boolean)?;
    check_json_value(json, "useParallel", Value::is_boolean)
}

fn map_settings(json: Value) -> Settings {
    Settings {
        smtp_host: json["smtpHost"].as_str().unwrap().to_string(),
        smtp_port: json["smtpPort"].as_u64().unwrap() as u32,
        from_address: json["fromAddress"].as_str().unwrap().to_string(),
        to_addresses: json["toAddresses"].as_array().unwrap().iter().map(|v| v.as_str().unwrap().to_string()).collect(),
        eml_files: json["emlFiles"].as_array().unwrap().iter().map(|v| v.as_str().unwrap().to_string()).collect(),
        update_date: json.get("updateDate").map(|v| v.as_bool().unwrap()).unwrap_or(true),
        update_message_id: json.get("updateMessageId").map(|v| v.as_bool().unwrap()).unwrap_or(true),
        use_parallel: json.get("useParallel").map(|v| v.as_bool().unwrap()).unwrap_or(false)
    }
}

fn replace_crlf_dot(cmd: &str) -> String {
    (if cmd == format!("{}.", CRLF) { "<CRLF>." } else { cmd }).to_string()
}

fn send_line(stream: &mut TcpStream, cmd: &str, use_parallel: bool) -> SendEmlResult<()> {
    println!("{}send: {}", make_id_prefix(use_parallel), replace_crlf_dot(cmd));

    stream.write_all(format!("{}{}", cmd, CRLF).as_bytes())?;
    stream.flush()?;

    Ok(())
}

fn is_last_reply(line: &str) -> bool {
    let re = regex::Regex::new(r"^\d{3} .+").unwrap();
    re.is_match(line)
}

fn is_positive_reply(line: &str) -> bool {
    match line.chars().next().unwrap_or_default() {
        '2' | '3' => true,
        _ => false
    }
}

type TcpReader = BufReader<TcpStream>;
type CmdResult = Result<String, SendEmlError>;

fn recv_line(reader: &mut TcpReader, use_parallel: bool) -> CmdResult {
    let mut line = String::new();

    loop {
        let size = reader.read_line(&mut line)?;
        if size == 0 {
            return Err(new_error("Connection closed by foreign host"))
        }

        line = line.trim().to_string();
        println!("{}recv: {}", make_id_prefix(use_parallel), line);
        if is_last_reply(&line) {
            return if is_positive_reply(&line) {
                Ok(line)
            } else {
                Err(new_error(&line))
            }
        }
        line.clear();
    }
}

fn send_mail(stream: &mut TcpStream, file: &str, update_date: bool, update_message_id: bool, use_parallel: bool) -> CmdResult {
    println!("{}send: {}", make_id_prefix(use_parallel), file);

    let buf = replace_mail(&fs::read(file)?, update_date, update_message_id);
    stream.write_all(&buf)?;
    stream.flush()?;

    Ok("".to_string())
}

fn make_send_cmd<'a>(reader: &'a mut TcpReader, use_parallel: bool) -> impl FnMut(&str) -> CmdResult + 'a {
    move |cmd| {
        send_line(reader.get_mut(), cmd, use_parallel)?;
        recv_line(reader, use_parallel)
    }
}

fn send_hello<F>(send: &mut F) -> CmdResult where F: FnMut(&str) -> CmdResult {
    send("EHLO localhost")
}

fn send_from<F>(send: &mut F, from_addr: &str) -> CmdResult where F: FnMut(&str) -> CmdResult {
    send(&format!("MAIL FROM: <{}>", from_addr))
}

fn send_rcpt_to<F>(send: &mut F, to_addrs: &Vec<String>) -> CmdResult where F: FnMut(&str) -> CmdResult {
    for addr in to_addrs {
        send(&format!("RCPT TO: <{}>", addr))?;
    }

    Ok("".to_string())
}

fn send_data<F>(send: &mut F) -> CmdResult where F: FnMut(&str) -> CmdResult {
    send("DATA")
}

fn send_crlf_dot<F>(send: &mut F) -> CmdResult where F: FnMut(&str) -> CmdResult {
    send(&format!("{}.", CRLF))
}

fn send_quit<F>(send: &mut F) -> CmdResult where F: FnMut(&str) -> CmdResult {
    send("QUIT")
}

fn send_rset<F>(send: &mut F) -> CmdResult where F: FnMut(&str) -> CmdResult {
    send("RSET")
}

fn make_connect_addr(host: &str, port: u32) -> String {
    format!("{}:{}", host, port)
}

fn send_messages(settings: &Settings, eml_files: &Vec<String>, use_parallel: bool) -> SendEmlResult<()> {
    let addr = make_connect_addr(&settings.smtp_host, settings.smtp_port);
    let mut stream = TcpStream::connect(addr)?;
    let mut reader = BufReader::new(stream.try_clone()?);
    let _ = recv_line(&mut reader, use_parallel)?;
    let mut send = make_send_cmd(&mut reader, use_parallel);

    send_hello(&mut send)?;

    let mut reset = false;
    for file in eml_files {
        if !Path::new(&file).is_file() {
            println!("{}: EML file does not exist", file);
            continue;
        }

        if reset {
            println!("---");
            send_rset(&mut send)?;
        }

        send_from(&mut send, &settings.from_address)?;
        send_rcpt_to(&mut send, &settings.to_addresses)?;
        send_data(&mut send)?;

        send_mail(&mut stream, &file, settings.update_date, settings.update_message_id, use_parallel)
            .map_err(|e| new_error(&format!("{}: {}", file, e)))?;

        send_crlf_dot(&mut send)?;
        reset = true;
    }

    send_quit(&mut send)?;
    Ok(())
}

fn proc_json(json_file: &str) -> SendEmlResult<()> {
    if !Path::new(json_file).is_file() {
        return Err(new_error("Json file does not exist"))
    }

    let json = get_settings(json_file)?;
    check_settings(&json)?;
    let settings = map_settings(json);
    let eml_files = &settings.eml_files;

    if settings.use_parallel && settings.eml_files.len() > 1 {
        eml_files.par_iter().for_each(|file| {
            if let Err(e) = send_messages(&settings, &vec![file.to_string()], true) {
                println!("error: {}: {}", json_file, e);
            }
        });
    } else {
        send_messages(&settings, eml_files, false)?;
    }

    Ok(())
}

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() == 1 {
        print_usage();
        process::exit(0);
    }

    if args[1] == "--version" {
        print_version();
        process::exit(0);
    }

    for json_file in &args[1..] {
        if let Err(e) = proc_json(json_file) {
            println!("error: {}: {}", json_file, e);
        }
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn make_now_date_line_test() {
        let line = super::make_now_date_line();
        assert!(line.starts_with("Date: "));
        assert!(line.ends_with(super::CRLF));
        assert!(line.len() <= 80)
    }

    #[test]
    fn make_random_message_id_line_test() {
        let line = super::make_random_message_id_line();
        assert!(line.starts_with("Message-ID: "));
        assert!(line.ends_with(super::CRLF));
        assert!(line.len() <= 80);
    }

    fn make_simple_mail_text() -> String {
        let mail = r#"From: a001 <a001@ah62.example.jp>
Subject: test
To: a002@ah62.example.jp
Message-ID: <b0e564a5-4f70-761a-e103-70119d1bcb32@ah62.example.jp>
Date: Sun, 26 Jul 2020 22:01:37 +0900
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:78.0) Gecko/20100101
 Thunderbird/78.0.1
MIME-Version: 1.0
Content-Type: text/plain; charset=utf-8; format=flowed
Content-Transfer-Encoding: 7bit
Content-Language: en-US

test"#;
        mail.replace("\n", "\r\n")
    }

    fn make_folded_mail() -> Vec<u8> {
        let mail = r#"From: a001 <a001@ah62.example.jp>
Subject: test
To: a002@ah62.example.jp
Message-ID:
 <b0e564a5-4f70-761a-e103-70119d1bcb32@ah62.example.jp>
Date:
 Sun, 26 Jul 2020
 22:01:37 +0900
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:78.0) Gecko/20100101
 Thunderbird/78.0.1
MIME-Version: 1.0
Content-Type: text/plain; charset=utf-8; format=flowed
Content-Transfer-Encoding: 7bit
Content-Language: en-US

test"#;
        mail.replace("\n", "\r\n").as_bytes().to_vec()
    }

    fn make_folded_end_date() -> Vec<u8> {
        let mail = r#"From: a001 <a001@ah62.example.jp>
Subject: test
To: a002@ah62.example.jp
Message-ID:
 <b0e564a5-4f70-761a-e103-70119d1bcb32@ah62.example.jp>
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:78.0) Gecko/20100101
 Thunderbird/78.0.1
MIME-Version: 1.0
Content-Type: text/plain; charset=utf-8; format=flowed
Content-Transfer-Encoding: 7bit
Content-Language: en-US
Date:
 Sun, 26 Jul 2020
 22:01:37 +0900
"#;
        mail.replace("\n", "\r\n").as_bytes().to_vec()
    }

    fn make_folded_end_message_id() -> Vec<u8> {
        let mail = r#"From: a001 <a001@ah62.example.jp>
Subject: test
To: a002@ah62.example.jp
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:78.0) Gecko/20100101
 Thunderbird/78.0.1
MIME-Version: 1.0
Content-Type: text/plain; charset=utf-8; format=flowed
Content-Transfer-Encoding: 7bit
Content-Language: en-US
Date:
 Sun, 26 Jul 2020
 22:01:37 +0900
Message-ID:
 <b0e564a5-4f70-761a-e103-70119d1bcb32@ah62.example.jp>
"#;
        mail.replace("\n", "\r\n").as_bytes().to_vec()
    }

    fn make_simple_mail() -> Vec<u8> {
        make_simple_mail_text().as_bytes().to_vec()
    }

    fn make_invalid_mail() -> Vec<u8> {
        make_simple_mail_text().replace("\r\n\r\n", "").as_bytes().to_vec()
    }

    fn get_header_line(header: &[u8], name: &str) -> Option<String> {
        let header_str = std::str::from_utf8(header).unwrap();
        let re = regex::Regex::new(&format!(r"({}:[\s\S]+?\r\n)([^ \t]|$)", name)).unwrap();
        let caps = re.captures(header_str).unwrap();
        caps.get(1).map(|c| c.as_str().to_string())
    }

    fn get_message_id_line(header: &[u8]) -> Option<String> {
        return get_header_line(header, "Message-ID")
    }

    fn get_date_line(header: &[u8]) -> Option<String> {
        return get_header_line(header, "Date")
    }

    #[test]
    fn get_header_line_test() {
        let mail = make_simple_mail();
        assert_eq!("Date: Sun, 26 Jul 2020 22:01:37 +0900\r\n", get_date_line(&mail).unwrap());
        assert_eq!("Message-ID: <b0e564a5-4f70-761a-e103-70119d1bcb32@ah62.example.jp>\r\n", get_message_id_line(&mail).unwrap());

        let f_mail = make_folded_mail();
        assert_eq!("Date:\r\n Sun, 26 Jul 2020\r\n 22:01:37 +0900\r\n", get_date_line(&f_mail).unwrap());
        assert_eq!("Message-ID:\r\n <b0e564a5-4f70-761a-e103-70119d1bcb32@ah62.example.jp>\r\n", get_message_id_line(&f_mail).unwrap());

        let e_date = make_folded_end_date();
        assert_eq!("Date:\r\n Sun, 26 Jul 2020\r\n 22:01:37 +0900\r\n", get_date_line(&e_date).unwrap());

        let e_message_id = make_folded_end_message_id();
        assert_eq!("Message-ID:\r\n <b0e564a5-4f70-761a-e103-70119d1bcb32@ah62.example.jp>\r\n", get_message_id_line(&e_message_id).unwrap());
    }

    #[test]
    fn replace_message_id_line_test() {
        let (header, _) = super::split_mail(&make_simple_mail()).unwrap();
        let repl_header = super::replace_message_id_line(&header);

        let orig_line = get_message_id_line(&header).unwrap();
        let repl_line = get_message_id_line(&repl_header).unwrap();
        assert_ne!(orig_line, repl_line);

        let date_line = get_header_line(&repl_header, "Date");
        assert!(date_line.is_some());
    }

    #[test]
    fn replace_date_line_test() {
        let (header, _) = super::split_mail(&make_simple_mail()).unwrap();
        let repl_header = super::replace_date_line(&header);

        let orig_line = get_date_line(&header).unwrap();
        let repl_line = get_date_line(&repl_header).unwrap();
        assert_ne!(orig_line, repl_line);

        let user_agent_line = get_header_line(&repl_header, "User-Agent");
        assert!(user_agent_line.is_some());
    }

    #[test]
    fn is_not_update_test() {
        assert_eq!(false, super::is_not_update(true, true));
        assert_eq!(false, super::is_not_update(true, false));
        assert_eq!(false, super::is_not_update(false, true));
        assert_eq!(true, super::is_not_update(false, false));
    }

    #[test]
    fn combine_mail_test() {
        let mail = make_simple_mail();
        let (header, body) = super::split_mail(&mail).unwrap();
        let new_mail = super::combine_mail(&header, &body);
        assert_eq!(mail, new_mail);
    }

    #[test]
    fn find_empty_line_test() {
        let mail = make_simple_mail();
        assert_eq!(414, super::find_empty_line(&mail).unwrap());

        let invalid_mail = make_invalid_mail();
        assert!(super::find_empty_line(&invalid_mail).is_none());
    }

    #[test]
    fn split_mail_test() {
        let mail = make_simple_mail();
        let header_body = super::split_mail(&mail);
        assert!(header_body.is_some());

        let (header, body) = header_body.unwrap();
        assert_eq!(mail.iter().take(414).copied().collect::<Vec<_>>(), header);
        assert_eq!(mail.iter().skip(414 + 4).copied().collect::<Vec<_>>(), body);

        let invalid_mail = make_invalid_mail();
        assert!(super::split_mail(&invalid_mail).is_none());
    }

    #[test]
    fn replace_header_test() {
        let (header, _) = super::split_mail(&make_simple_mail()).unwrap();
        let date_line = get_date_line(&header).unwrap();
        let mid_line = get_message_id_line(&header).unwrap();

        let repl_header = super::replace_header(&header, false, false);
        assert_eq!(header, repl_header);

        let replace = |header: &Vec<u8>, update_date: bool, update_message_id: bool| -> (String, String) {
            let r_header = super::replace_header(header, update_date, update_message_id);
            (get_date_line(&r_header).unwrap(), get_message_id_line(&r_header).unwrap())
        };

        let (r_date_line, r_mid_line) = replace(&header, true, true);
        assert_ne!(date_line, r_date_line);
        assert_ne!(mid_line, r_mid_line);

        let (r_date_line, r_mid_line) = replace(&header, true, false);
        assert_ne!(date_line, r_date_line);
        assert_eq!(mid_line, r_mid_line);

        let (r_date_line, r_mid_line) = replace(&header, false, true);
        assert_eq!(date_line, r_date_line);
        assert_ne!(mid_line, r_mid_line);

        let (folded_header, _) = super::split_mail(&make_folded_mail()).unwrap();
        let (f_date_line, f_mid_line) = replace(&folded_header, true, true);
        assert_eq!(1, f_date_line.chars().filter(|&c| c == '\n').count());
        assert_eq!(1, f_mid_line.chars().filter(|&c| c == '\n').count());
    }

    #[test]
    fn replace_mail_test() {
        let mail = make_simple_mail();
        let repl_mail = super::replace_mail(&mail, false, false);
        assert_eq!(mail, repl_mail);

        let invalid_mail = make_invalid_mail();
        assert_eq!(invalid_mail, super::replace_mail(&invalid_mail, true, true));

        let repl_mail = super::replace_mail(&mail, true, true);
        assert_ne!(mail, repl_mail);

        let mail_last100 = mail[(mail.len() - 100)..mail.len()].to_vec();
        let repl_mail_last100 = repl_mail[(repl_mail.len() - 100)..repl_mail.len()].to_vec();
        assert_eq!(mail_last100, repl_mail_last100);
    }

    #[test]
    fn replace_crlf_dot_test() {
        assert_eq!("TEST", super::replace_crlf_dot("TEST"));
        assert_eq!("CRLF", super::replace_crlf_dot("CRLF"));
        assert_eq!(super::CRLF, super::replace_crlf_dot(super::CRLF));
        assert_eq!(".", super::replace_crlf_dot("."));
        assert_eq!("<CRLF>.", super::replace_crlf_dot(&format!("{}.", super::CRLF)));
    }

    #[test]
    fn is_last_reply_test() {
        assert_eq!(false, super::is_last_reply(&"250-First line".to_string()));
        assert_eq!(false, super::is_last_reply(&"250-Second line".to_string()));
        assert_eq!(false, super::is_last_reply(&"250-234 Text beginning with numbers".to_string()));
        assert_eq!(true, super::is_last_reply(&"250 The last line".to_string()));
    }

    #[test]
    fn is_positive_reply_test() {
        assert_eq!(true, super::is_positive_reply(&"200 xxx".to_string()));
        assert_eq!(true, super::is_positive_reply(&"300 xxx".to_string()));
        assert_eq!(false, super::is_positive_reply(&"400 xxx".to_string()));
        assert_eq!(false, super::is_positive_reply(&"500 xxx".to_string()));
        assert_eq!(false, super::is_positive_reply(&"xxx 200".to_string()));
        assert_eq!(false, super::is_positive_reply(&"xxx 300".to_string()));
    }

    #[test]
    fn get_and_map_settings() {
        let json = super::make_json_sample();
        let settings = super::map_settings(super::get_settings_from_text(&json).unwrap());

        assert_eq!("172.16.3.151", settings.smtp_host);
        assert_eq!(25, settings.smtp_port);
        assert_eq!("a001@ah62.example.jp", settings.from_address);

        let to_addr1: Vec<String> = vec!["a001@ah62.example.jp", "a002@ah62.example.jp", "a003@ah62.example.jp"].iter().map(|s| s.to_string()).collect();
        let to_addr2: Vec<String> = settings.to_addresses;
        assert_eq!(to_addr1, to_addr2);

        let eml_file1: Vec<String> = vec!["test1.eml", "test2.eml", "test3.eml"].iter().map(|s| s.to_string()).collect();
        let eml_file2: Vec<String> = settings.eml_files;
        assert_eq!(eml_file1, eml_file2);

        assert_eq!(true, settings.update_date);
        assert_eq!(true, settings.update_message_id);
        assert_eq!(false, settings.use_parallel);
    }

    #[test]
    fn check_settings_test() {
        fn check_no_key(key: &str) -> super::SendEmlResult<()> {
            let json = super::make_json_sample();
            let re = regex::Regex::new(key).unwrap();
            let no_key = re.replace(&json, format!("X-{}", key).as_str());
            super::check_settings(&super::get_settings_from_text(&no_key.to_string()).unwrap())
        }

        assert!(check_no_key("smtpHost").is_err());
        assert!(check_no_key("smtpPort").is_err());
        assert!(check_no_key("fromAddress").is_err());
        assert!(check_no_key("toAddresses").is_err());
        assert!(check_no_key("emlFiles").is_err());
        assert!(check_no_key("updateDate").is_ok());
        assert!(check_no_key("updateMessageId").is_ok());
        assert!(check_no_key("useParallel").is_ok());
    }

    fn make_test_send_cmd<'a>(expected: &'a str) -> impl FnMut(&str) -> super::CmdResult + 'a {
        move |cmd| {
            assert_eq!(expected, cmd);
            Ok(cmd.to_owned())
        }
    }

    #[test]
    fn send_hello_test() {
        let _ = super::send_hello(&mut make_test_send_cmd("EHLO localhost"));
    }

    #[test]
    fn send_from_test() {
        let _ = super::send_from(&mut make_test_send_cmd("MAIL FROM: <a001@ah62.example.jp>"), "a001@ah62.example.jp");
    }

    #[test]
    fn send_rcpt_test() {
        let mut count = 1;
        let mut test_func = |cmd: &str| {
            assert_eq!(format!("RCPT TO: <a00{}@ah62.example.jp>", count), cmd);
            count += 1;
            Ok(cmd.to_owned())
        };

        let _ = super::send_rcpt_to(&mut test_func, &vec!["a001@ah62.example.jp".into(), "a002@ah62.example.jp".into(), "a003@ah62.example.jp".into()]);
    }

    #[test]
    fn send_data_test() {
        let _ = super::send_data(&mut make_test_send_cmd("DATA"));
    }

    #[test]
    fn send_crlf_dot_test() {
        let _ = super::send_crlf_dot(&mut make_test_send_cmd(&format!("{}.", super::CRLF)));
    }

    #[test]
    fn send_quit_test() {
        let _ = super::send_quit(&mut make_test_send_cmd("QUIT"));
    }

    #[test]
    fn send_rset_test() {
        let _ = super::send_rset(&mut make_test_send_cmd("RSET"));
    }

    use serde_json::Value;

    #[test]
    fn check_json_value_test() {
        fn check(json: &str, pred: super::ValuePred) -> super::SendEmlResult<()> {
            let v: Value = serde_json::from_str(json).unwrap();
            super::check_json_value(&v, "test", pred)
        }

        fn check_error(json: &str, pred: super::ValuePred, expected: &str) {
            let res = check(&json, pred);
            assert!(res.is_err());
            assert_eq!(expected, &res.err().unwrap().to_string());
        }

        let json = r#"{"test": "172.16.3.151"}"#;
        assert!(check(&json, Value::is_string).is_ok());
        assert!(check(&json, Value::is_number).is_err());
        check_error(&json, Value::is_boolean, "test: Invalid type: \"172.16.3.151\"");

        let json = r#"{"test": 172}"#;
        assert!(check(&json, Value::is_number).is_ok());
        assert!(check(&json, Value::is_string).is_err());
        check_error(&json, Value::is_boolean, "test: Invalid type: 172");

        let json = r#"{"test": true}"#;
        assert!(check(&json, Value::is_boolean).is_ok());
        assert!(check(&json, Value::is_string).is_err());
        check_error(&json, Value::is_number, "test: Invalid type: true");

        let json = r#"{"test": false}"#;
        assert!(check(&json, Value::is_boolean).is_ok());
        assert!(check(&json, Value::is_string).is_err());
        check_error(&json, Value::is_number, "test: Invalid type: false");
    }

    #[test]
    fn check_json_array_value_test() {
        fn check(json: &str, pred: super::ValuePred) -> super::SendEmlResult<()> {
            let v: Value = serde_json::from_str(json).unwrap();
            super::check_json_array_value(&v, "test", pred)
        }

        fn check_error(json: &str, pred: super::ValuePred, expected: &str) {
            let res = check(&json, pred);
            assert!(res.is_err());
            assert_eq!(expected, &res.err().unwrap().to_string());
        }

        let json = r#"{"test": ["172.16.3.151", "172.16.3.152", "172.16.3.153"]}"#;
        assert!(check(json, Value::is_string).is_ok());

        let json = r#"{"test": "172.16.3.151"}"#;
        check_error(json, Value::is_string, "test: Invalid type (array): \"172.16.3.151\"");

        let json = r#"{"test": ["172.16.3.151", "172.16.3.152", 172]}"#;
        check_error(json, Value::is_string, "test: Invalid type (element): 172");
    }
}