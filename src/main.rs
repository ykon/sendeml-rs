/**
 * Copyright (c) Yuki Ono.
 * Licensed under the MIT License.
 */

#[macro_use]
extern crate lazy_static;

use std::env;
use std::fs;
use std::fmt;
use std::io::BufReader;
use std::io::prelude::*;
use std::net::TcpStream;
use std::path::Path;
use std::process;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::Duration;
use chrono::prelude::*;
use rand::{thread_rng, Rng};
use rand::distributions::Alphanumeric;
use rayon::prelude::*;
use regex::bytes::Regex;
use serde::Deserialize;

const CRLF: &str = "\r\n";
const VERSION: f64 = 1.0;

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

fn replace_message_id_line(file_buf: &Vec<u8>) -> Vec<u8> {
    let re = Regex::new(r"Message-ID: \S+\r\n").unwrap();
    re.replace(file_buf, make_random_message_id_line().as_bytes()).to_vec()
}

fn replace_date_line(file_buf: &Vec<u8>) -> Vec<u8> {
    let re = Regex::new(r"Date: [\S ]+\r\n").unwrap();
    re.replace(&file_buf, make_now_date_line().as_bytes()).to_vec()
}

fn replace_raw_bytes(file_buf: Vec<u8>, update_date: bool, update_message_id: bool) -> Vec<u8> {
    match (update_date, update_message_id) {
        (true, true) => replace_message_id_line(&replace_date_line(&file_buf)),
        (true, false) => replace_date_line(&file_buf),
        (false, true) => replace_message_id_line(&file_buf),
        (false, false) => file_buf
    }
}

fn make_json_sample() -> String {
    let json = r#"{
    "smtpHost": "172.16.3.151",
    "smtpPort": 25,
    "fromAddress": "a001@ah62.example.jp",
    "toAddress": [
        "a001@ah62.example.jp",
        "a002@ah62.example.jp",
        "a003@ah62.example.jp"
    ],
    "emlFile": [
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

lazy_static! {
    static ref USE_PARALLEL: AtomicBool = AtomicBool::new(false);
}

fn get_current_id_prefix() -> String {
    return if (*USE_PARALLEL).load(Ordering::Relaxed) {
        format!("{:?}, ", thread::current().id())
    } else {
        "".to_string()
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Settings {
    smtp_host: Option<String>,
    smtp_port: Option<u32>,
    from_address: Option<String>,
    to_address: Option<Vec<String>>,
    eml_file: Option<Vec<String>>,
    update_date: Option<bool>,
    update_message_id: Option<bool>,
    use_parallel: Option<bool>
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
    SendEmlError::StrError(msg.to_string())
}

fn get_settings_from_text(text: &String) -> SendEmlResult<Settings> {
    serde_json::from_str(&text).map_err(|e| SendEmlError::JsonError(e))
}

fn get_settings(json_file: &String) -> SendEmlResult<Settings> {
    get_settings_from_text(&fs::read_to_string(json_file)?)
}

fn check_settings(s: Settings) -> SendEmlResult<Settings> {
    let key = if s.smtp_host.is_none() {
        "smtpHost"
    } else if s.smtp_port.is_none() {
        "smtpPort"
    } else if s.from_address.is_none() {
        "fromAddress"
    } else if s.to_address.is_none() {
        "toAddress"
    } else if s.eml_file.is_none() {
        "emlFile"
    } else {
        ""
    };

    if key != "" {
        Err(new_error(&format!("{} key does not exist", key)))
    } else {
        Ok(s)
    }
}

fn replace_crlf_dot(cmd: &str) -> String {
    (if cmd == format!("{}.", CRLF) { "<CRLF>." } else { cmd }).to_string()
}

fn send_line(stream: &mut TcpStream, cmd: &str) -> SendEmlResult<()> {
    println!("{}send: {}", get_current_id_prefix(), replace_crlf_dot(cmd));

    stream.write_all(format!("{}{}", cmd, CRLF).as_bytes())?;
    stream.flush()?;

    Ok(())
}

fn is_last_reply(line: &String) -> bool {
    let re = regex::Regex::new(r"^\d{3} .+").unwrap();
    re.is_match(&line)
}

fn is_positive_reply(line: &String) -> bool {
    match line.chars().next().unwrap_or_default() {
        '2' | '3' => true,
        _ => false
    }
}

type TcpReader = BufReader<TcpStream>;
type CmdResult = Result<String, SendEmlError>;

fn recv_line(reader: &mut TcpReader) -> CmdResult {
    let mut line = String::new();

    loop {
        let size = reader.read_line(&mut line)?;
        if size == 0 {
            return Err(new_error("Connection closed by foreign host"))
        }

        line = line.trim().to_string();
        println!("{}recv: {}", get_current_id_prefix(), line);
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

fn send_cmd(reader: &mut TcpReader, cmd: &str) -> CmdResult {
    send_line(reader.get_mut(), cmd)?;
    recv_line(reader)
}

fn send_raw_bytes(stream: &mut TcpStream, file: &String, update_date: bool, update_message_id: bool) -> CmdResult {
    println!("{}send: {}", get_current_id_prefix(), file);

    let buf = replace_raw_bytes(fs::read(file)?, update_date, update_message_id);
    stream.write_all(&buf)?;
    stream.flush()?;

    Ok("".to_string())
}

fn send_hello(reader: &mut TcpReader) -> CmdResult {
    send_cmd(reader, "EHLO localhost")
}

fn send_from(reader: &mut TcpReader, from_addr: &String) -> CmdResult {
    send_cmd(reader, &format!("MAIL FROM: <{}>", from_addr))
}

fn send_rcpt_to(reader: &mut TcpReader, to_addrs: &Vec<String>) -> CmdResult {
    for addr in to_addrs {
        send_cmd(reader, &format!("RCPT TO: <{}>", addr))?;
    }

    Ok("".to_string())
}

fn send_data(reader: &mut TcpReader) -> CmdResult {
    send_cmd(reader, "DATA")
}

fn send_crlf_dot(reader: &mut TcpReader) -> CmdResult {
    send_cmd(reader, &format!("{}.", CRLF))
}

fn send_quit(reader: &mut TcpReader) -> CmdResult {
    send_cmd(reader, "QUIT")
}

fn send_rset(reader: &mut TcpReader) -> CmdResult {
    send_cmd(reader, "RSET")
}

fn make_connect_addr(host: &String, port: u32) -> String {
    format!("{}:{}", host, port)
}

fn send_messages(settings: &Settings, eml_files: &Vec<String>) -> SendEmlResult<()> {
    let addr = make_connect_addr(settings.smtp_host.as_ref().unwrap(), settings.smtp_port.unwrap());
    let mut stream = TcpStream::connect(addr)?;
    stream.set_read_timeout(Some(Duration::new(1000, 0)))?;

    let mut reader = BufReader::new(stream.try_clone()?);
    let _ = recv_line(&mut reader)?;
    send_hello(&mut reader)?;

    let mut mail_sent = false;
    for file in eml_files {
        if !Path::new(&file).is_file() {
            println!("{}: EML file does not exist", file);
            continue;
        }

        if mail_sent {
            println!("---");
            send_rset(&mut reader)?;
        }

        send_from(&mut reader, settings.from_address.as_ref().unwrap())?;
        send_rcpt_to(&mut reader, settings.to_address.as_ref().unwrap())?;
        send_data(&mut reader)?;
        send_raw_bytes(&mut stream, &file, settings.update_date.unwrap_or(true), settings.update_message_id.unwrap_or(true))?;
        send_crlf_dot(&mut reader)?;
        mail_sent = true;
    }

    send_quit(&mut reader)?;
    Ok(())
}

fn send_one_message(settings: &Settings, file: &String) -> SendEmlResult<()> {
    send_messages(settings, &vec![file.to_string()])
}

fn proc_json(json_file: &String) -> SendEmlResult<()> {
    if !Path::new(json_file).is_file() {
        return Err(new_error("Json file does not exist"))
    }

    let settings = check_settings(get_settings(json_file)?)?;
    let eml_files = settings.eml_file.as_ref().unwrap();

    if settings.use_parallel.unwrap_or(false) {
        (*USE_PARALLEL).store(true, Ordering::Relaxed);
        eml_files.par_iter().for_each(|file| {
            if let Err(e) = send_one_message(&settings, file) {
                println!("{}: {}", json_file, e);
            }
        });
    } else {
        send_messages(&settings, eml_files)?;
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
            println!("{}: {}", json_file, e);
        }
    }
}

#[cfg(test)]
mod tests {
    use regex::Regex;

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

    fn make_simple_mail() -> String {
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
        mail.to_string()
    }

    fn get_message_id_line(mail: &String) -> Option<String> {
        let re = Regex::new(r"Message-ID: \S+\r\n").unwrap();
        re.find(&mail).map(|m| m.as_str().to_string())
    }

    #[test]
    fn replace_message_id_line_test() {
        let mail = make_simple_mail().replace("\n", "\r\n");
        let repl_mail = String::from_utf8(super::replace_message_id_line(&mail.as_bytes().to_vec())).unwrap();

        let orig_line = get_message_id_line(&mail).unwrap();
        let repl_line = get_message_id_line(&repl_mail).unwrap();
        assert_ne!(orig_line, repl_line);
    }

    fn get_date_line(mail: &String) -> Option<String> {
        let re = Regex::new(r"Date: [\S ]+\r\n").unwrap();
        re.find(&mail).map(|m| m.as_str().to_string())
    }

    #[test]
    fn replace_date_line_test() {
        let mail = make_simple_mail().replace("\n", "\r\n");
        let repl_mail = String::from_utf8(super::replace_date_line(&mail.as_bytes().to_vec())).unwrap();

        let orig_line = get_date_line(&mail).unwrap();
        let repl_line = get_date_line(&repl_mail).unwrap();
        assert_ne!(orig_line, repl_line);
    }

    #[test]
    fn replace_raw_bytes_test() {
        let mail = make_simple_mail().replace("\n", "\r\n");
        let orig_date_line = get_date_line(&mail).unwrap_or_default();
        let orig_mid_line = get_message_id_line(&mail).unwrap_or_default();

        {
            let repl_mail = String::from_utf8(super::replace_raw_bytes(mail.as_bytes().to_vec(), true, true)).unwrap();
            let repl_date_line = get_date_line(&repl_mail).unwrap();
            let repl_mid_line = get_message_id_line(&repl_mail).unwrap();

            assert_ne!(orig_date_line, repl_date_line);
            assert_ne!(orig_mid_line, repl_mid_line)
        }

        {
            let repl_mail = String::from_utf8(super::replace_raw_bytes(mail.as_bytes().to_vec(), true, false)).unwrap();
            let repl_date_line = get_date_line(&repl_mail).unwrap();
            let repl_mid_line = get_message_id_line(&repl_mail).unwrap();

            assert_ne!(orig_date_line, repl_date_line);
            assert_eq!(orig_mid_line, repl_mid_line)
        }

        {
            let repl_mail = String::from_utf8(super::replace_raw_bytes(mail.as_bytes().to_vec(), false, true)).unwrap();
            let repl_date_line = get_date_line(&repl_mail).unwrap();
            let repl_mid_line = get_message_id_line(&repl_mail).unwrap();

            assert_eq!(orig_date_line, repl_date_line);
            assert_ne!(orig_mid_line, repl_mid_line)
        }

        {
            let repl_mail = String::from_utf8(super::replace_raw_bytes(mail.as_bytes().to_vec(), false, false)).unwrap();
            let repl_date_line = get_date_line(&repl_mail).unwrap();
            let repl_mid_line = get_message_id_line(&repl_mail).unwrap();

            assert_eq!(orig_date_line, repl_date_line);
            assert_eq!(orig_mid_line, repl_mid_line)
        }
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
        assert!(!super::is_last_reply(&"250-First line".to_string()));
        assert!(!super::is_last_reply(&"250-Second line".to_string()));
        assert!(!super::is_last_reply(&"250-234 Text beginning with numbers".to_string()));
        assert!(super::is_last_reply(&"250 The last line".to_string()));
    }

    #[test]
    fn is_positive_reply_test() {
        assert!(super::is_positive_reply(&"200 xxx".to_string()));
        assert!(super::is_positive_reply(&"300 xxx".to_string()));
        assert!(!super::is_positive_reply(&"400 xxx".to_string()));
        assert!(!super::is_positive_reply(&"500 xxx".to_string()));
        assert!(!super::is_positive_reply(&"xxx 200".to_string()));
        assert!(!super::is_positive_reply(&"xxx 300".to_string()));
    }

    fn match_vec<T: PartialEq>(a: &Vec<T>, b: &Vec<T>) -> bool {
        a.iter().zip(b.iter()).find(|&(a, b)| a != b).is_none()
    }

    #[test]
    fn get_settings_from_text_test() {
        let json = super::make_json_sample();
        let settings = super::get_settings_from_text(&json).unwrap();

        assert_eq!("172.16.3.151", settings.smtp_host.as_deref().unwrap());
        assert_eq!(25, settings.smtp_port.unwrap());
        assert_eq!("a001@ah62.example.jp", settings.from_address.as_deref().unwrap());

        let to_addr1: Vec<String> = vec!["a001@ah62.example.jp", "a002@ah62.example.jp", "a003@ah62.example.jp"].iter().map(|s| s.to_string()).collect();
        let to_addr2: Vec<String> = settings.to_address.unwrap();
        assert!(match_vec(&to_addr1, &to_addr2));

        let eml_file1: Vec<String> = vec!["test1.eml", "test2.eml", "test3.eml"].iter().map(|s| s.to_string()).collect();
        let eml_file2: Vec<String> = settings.eml_file.unwrap();
        assert!(match_vec(&eml_file1, &eml_file2));

        assert_eq!(true, settings.update_date.unwrap());
        assert_eq!(true, settings.update_message_id.unwrap());
        assert_eq!(false, settings.use_parallel.unwrap());
    }

    #[test]
    fn check_settings_test() {
        fn check_no_key(key: &str) -> super::SendEmlResult<super::Settings> {
            let json = super::make_json_sample();
            let re = Regex::new(key).unwrap();
            let no_key = re.replace(&json, format!("X-{}", key).as_str());
            super::check_settings(super::get_settings_from_text(&no_key.to_string()).unwrap())
        }

        assert!(check_no_key("smtpHost").is_err());
        assert!(check_no_key("smtpPort").is_err());
        assert!(check_no_key("fromAddress").is_err());
        assert!(check_no_key("toAddress").is_err());
        assert!(check_no_key("emlFile").is_err());
        assert!(check_no_key("testKey").is_ok());
    }
}