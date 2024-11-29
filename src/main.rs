use inotify::{Inotify, WatchMask};
use std::ffi::OsString;
use std::fs::File;
use std::io::{self, BufRead};
use std::os::unix::ffi::OsStringExt;
use std::os::unix::process::ExitStatusExt;
use std::path::Path;
use std::process::{exit, ExitStatus, Output};
use std::time::{SystemTime, UNIX_EPOCH};
use totp_lite::{totp_custom, Sha1, DEFAULT_STEP};

const HELP: &str = "\
Execute command on FILE modification

Usage: watchc -w <FILE> -c <COMMAND>

Options:
  -w, --watch <FILE>        Watch <FILE> for modification
  -c, --command <COMMAND>   Execute <COMMAND> on watch modification

  -p, --password <PASS>     Set TOTP secret to <PASS>
  -f, --passfile <FILE>     Set TOTP secret from first line in <FILE>
  -q, --quiet               Do not print command outputs
  -n, --no-password         Don't check for TOTP in watch
  -h, --help                Print help
  -V, --version             Print version";

struct Args {
    watch: OsString,
    password: Vec<u8>,
    command: String,
    quiet: bool,
    nopass: bool,
}

fn parse_args() -> Result<Args, lexopt::Error> {
    use lexopt::prelude::*;

    let mut watch = OsString::new();
    let mut password = b"secret".to_vec();
    let mut passfile = OsString::new();
    let mut command = String::new();
    let mut quiet = false;
    let mut nopass = false;

    let mut parser = lexopt::Parser::from_env();

    while let Some(arg) = parser.next()? {
        match arg {
            Short('w') | Long("watch") => {
                watch = parser.value()?.parse()?;
            }
            Short('p') | Long("password") => {
                password = parser.value()?.into_vec();
            }
            Short('f') | Long("passfile") => {
                passfile = parser.value()?.parse()?;
            }
            Short('c') | Long("command") => {
                command = parser.value()?.string()?;
            }
            Short('q') | Long("quiet") => {
                quiet = true;
            }
            Short('n') | Long("no-password") => {
                nopass = true;
            }
            Short('h') | Long("help") => {
                println!("{HELP}");
                exit(0);
            }
            Short('V') | Long("version") => {
                println!("{} {}", env!("CARGO_BIN_NAME"), env!("CARGO_PKG_VERSION"));
                exit(0);
            }
            _ => return Err(arg.unexpected()),
        }
    }

    if watch.is_empty() || command.is_empty() {
        eprintln!("Please provide watch & command");
        exit(1);
    }

    if !passfile.is_empty() {
        if let Ok(lines) = read_lines(passfile) {
            for line in lines.take(1).map_while(Result::ok) {
                password = line.into();
            }
        }
    }

    Ok(Args {
        watch,
        password,
        command,
        quiet,
        nopass,
    })
}

fn get_secrets(p: &[u8]) -> Vec<String> {
    let seconds: u64 = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();

    [
        totp_custom::<Sha1>(DEFAULT_STEP, 6, p, seconds - DEFAULT_STEP),
        totp_custom::<Sha1>(DEFAULT_STEP, 6, p, seconds),
        totp_custom::<Sha1>(DEFAULT_STEP, 6, p, seconds + DEFAULT_STEP),
    ]
    .to_vec()
}

fn read_lines<P>(filename: P) -> io::Result<io::Lines<io::BufReader<File>>>
where
    P: AsRef<Path>,
{
    let file = File::open(filename)?;
    Ok(io::BufReader::new(file).lines())
}

fn watch_path(args: &Args) {
    let mut inotify = Inotify::init().expect("Failed to initialize inotify");
    let path = Path::new(&args.watch);
    let Some(parent) = path.parent() else {
        eprintln!("Failed to determine path");
        exit(1);
    };

    inotify
        .watches()
        .add(parent, WatchMask::CLOSE_WRITE)
        .expect("Failed to add inotify watch");

    let mut buffer = [0u8; 4096];
    loop {
        let events = inotify
            .read_events_blocking(&mut buffer)
            .expect("Failed to read inotify events");

        for event in events {
            if event.name == path.file_name() {
                if args.nopass {
                    let output = run(&args.command);
                    if !args.quiet {
                        print!("{}", String::from_utf8_lossy(&output.stdout));
                        eprint!("{}", String::from_utf8_lossy(&output.stderr));
                    }
                } else if let Ok(lines) = read_lines(path) {
                    let secrets = get_secrets(&args.password);
                    // println!("{secrets:?}");
                    for line in lines.take(1).map_while(Result::ok) {
                        if secrets.contains(&line) {
                            let output = run(&args.command);
                            if !args.quiet {
                                print!("{}", String::from_utf8_lossy(&output.stdout));
                                eprint!("{}", String::from_utf8_lossy(&output.stderr));
                            }
                        }
                    }
                }
            }
        }
    }
}

fn run(c: &String) -> Output {
    let mut shell = std::process::Command::new("sh");

    match shell.arg("-c").arg(c).output() {
        Ok(o) => o,
        Err(_) => Output {
            status: ExitStatus::from_raw(1),
            stdout: Vec::new(),
            stderr: Vec::new(),
        },
    }
}

fn main() {
    let args = match parse_args() {
        Ok(args) => args,
        Err(e) => {
            eprintln!("ERROR: {e}");
            exit(1);
        }
    };

    watch_path(&args);
}
