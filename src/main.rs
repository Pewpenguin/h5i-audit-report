use std::env;
use std::fs;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use h5i_audit_report::{parse_audit, render_report};

fn main() -> ExitCode {
    match run(env::args().skip(1).collect()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("error: {err}");
            ExitCode::FAILURE
        }
    }
}

fn run(args: Vec<String>) -> Result<(), String> {
    match parse_args(&args)? {
        Command::Help => {
            print!("{HELP}");
            Ok(())
        }
        Command::Version => {
            println!("h5i-audit-report {}", env!("CARGO_PKG_VERSION"));
            Ok(())
        }
        Command::Run(opts) => {
            let json = read_input(&opts.input)?;
            let audit = parse_audit(&json).map_err(|e| e.to_string())?;
            let html = render_report(&audit);
            write_output(&opts.output, &html)
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
enum Command {
    Help,
    Version,
    Run(Options),
}

#[derive(Debug, PartialEq, Eq)]
struct Options {
    /// `None` means read stdin.
    input: Option<PathBuf>,
    /// `None` means write stdout.
    output: Option<PathBuf>,
}

fn parse_args(args: &[String]) -> Result<Command, String> {
    let mut input: Option<PathBuf> = None;
    let mut output: Option<PathBuf> = None;
    let mut i = 0;

    while i < args.len() {
        let arg = &args[i];
        match arg.as_str() {
            "-h" | "--help" => return Ok(Command::Help),
            "-V" | "--version" => return Ok(Command::Version),
            "--out" => {
                i += 1;
                let Some(path) = args.get(i) else {
                    return Err("missing value for `--out` (expected a file path)".into());
                };
                if path.is_empty() {
                    return Err("`--out` path must not be empty".into());
                }
                if output.is_some() {
                    return Err("`--out` specified more than once".into());
                }
                output = Some(PathBuf::from(path));
            }
            s if s.starts_with("--out=") => {
                let path = &s["--out=".len()..];
                if path.is_empty() {
                    return Err("`--out` path must not be empty".into());
                }
                if output.is_some() {
                    return Err("`--out` specified more than once".into());
                }
                output = Some(PathBuf::from(path));
            }
            s if s.starts_with('-') => {
                return Err(format!("unknown option `{s}`\n\n{HELP}"));
            }
            s => {
                if input.is_some() {
                    return Err(format!(
                        "unexpected extra argument `{s}` (only one input path is allowed)"
                    ));
                }
                input = Some(PathBuf::from(s));
            }
        }
        i += 1;
    }

    Ok(Command::Run(Options { input, output }))
}

fn read_input(input: &Option<PathBuf>) -> Result<String, String> {
    match input {
        Some(path) => {
            fs::read_to_string(path).map_err(|e| format!("failed to read {}: {e}", path.display()))
        }
        None => {
            let mut buf = String::new();
            io::stdin()
                .read_to_string(&mut buf)
                .map_err(|e| format!("failed to read stdin: {e}"))?;
            Ok(buf)
        }
    }
}

fn write_output(output: &Option<PathBuf>, html: &str) -> Result<(), String> {
    match output {
        Some(path) => write_file(path, html),
        None => {
            let mut stdout = io::stdout().lock();
            stdout
                .write_all(html.as_bytes())
                .map_err(|e| format!("failed to write stdout: {e}"))
        }
    }
}

fn write_file(path: &Path, html: &str) -> Result<(), String> {
    fs::write(path, html).map_err(|e| format!("failed to write {}: {e}", path.display()))
}

const HELP: &str = "\
h5i-audit-report — turn an h5i browser audit JSON into a portable HTML report

Usage:
  h5i-audit-report [OPTIONS] [INPUT]

Arguments:
  [INPUT]  Path to a session audit JSON file (default: read stdin)

Options:
  --out <PATH>  Write the HTML report to PATH (default: write stdout)
  -h, --help    Show this help
  -V, --version Show version

Examples:
  h5i-audit-report audit.json --out report.html
  h5i-audit-report audit.json
  h5i browser audit --json | h5i-audit-report > report.html
  h5i browser audit --json | h5i-audit-report --out report.html
";

#[cfg(test)]
mod tests {
    use super::*;

    fn args(parts: &[&str]) -> Vec<String> {
        parts.iter().map(|s| (*s).to_string()).collect()
    }

    #[test]
    fn file_in_file_out() {
        assert_eq!(
            parse_args(&args(&["audit.json", "--out", "report.html"])).unwrap(),
            Command::Run(Options {
                input: Some(PathBuf::from("audit.json")),
                output: Some(PathBuf::from("report.html")),
            })
        );
    }

    #[test]
    fn file_in_stdout() {
        assert_eq!(
            parse_args(&args(&["audit.json"])).unwrap(),
            Command::Run(Options {
                input: Some(PathBuf::from("audit.json")),
                output: None,
            })
        );
    }

    #[test]
    fn stdin_stdout() {
        assert_eq!(
            parse_args(&args(&[])).unwrap(),
            Command::Run(Options {
                input: None,
                output: None,
            })
        );
    }

    #[test]
    fn stdin_with_out() {
        assert_eq!(
            parse_args(&args(&["--out", "report.html"])).unwrap(),
            Command::Run(Options {
                input: None,
                output: Some(PathBuf::from("report.html")),
            })
        );
    }

    #[test]
    fn out_before_input() {
        assert_eq!(
            parse_args(&args(&["--out", "report.html", "audit.json"])).unwrap(),
            Command::Run(Options {
                input: Some(PathBuf::from("audit.json")),
                output: Some(PathBuf::from("report.html")),
            })
        );
    }

    #[test]
    fn out_equals_form() {
        assert_eq!(
            parse_args(&args(&["audit.json", "--out=report.html"])).unwrap(),
            Command::Run(Options {
                input: Some(PathBuf::from("audit.json")),
                output: Some(PathBuf::from("report.html")),
            })
        );
    }

    #[test]
    fn help_and_version() {
        assert_eq!(parse_args(&args(&["--help"])).unwrap(), Command::Help);
        assert_eq!(parse_args(&args(&["-h"])).unwrap(), Command::Help);
        assert_eq!(parse_args(&args(&["--version"])).unwrap(), Command::Version);
        assert_eq!(parse_args(&args(&["-V"])).unwrap(), Command::Version);
    }

    #[test]
    fn rejects_extra_positional() {
        let err = parse_args(&args(&["a.json", "b.json"])).unwrap_err();
        assert!(err.contains("unexpected extra argument"), "{err}");
    }

    #[test]
    fn rejects_missing_out_value() {
        let err = parse_args(&args(&["--out"])).unwrap_err();
        assert!(err.contains("missing value for `--out`"), "{err}");
    }

    #[test]
    fn rejects_empty_out_value() {
        let err = parse_args(&args(&["--out="])).unwrap_err();
        assert!(err.contains("must not be empty"), "{err}");
    }

    #[test]
    fn rejects_unknown_option() {
        let err = parse_args(&args(&["--wat"])).unwrap_err();
        assert!(err.contains("unknown option"), "{err}");
    }

    #[test]
    fn end_to_end_file_roundtrip() {
        let dir = std::env::temp_dir().join(format!("h5i-audit-report-cli-{}", std::process::id()));
        let _ = fs::create_dir_all(&dir);
        let input = dir.join("audit.json");
        let output = dir.join("report.html");

        let json = r#"{
            "session": {
                "id": "br_cli",
                "url": "https://example.com/",
                "placement": {"kind": "host"},
                "engine": "h5i-light",
                "lane": "engine-claimed",
                "started_at": "2026-01-01T00:00:00.000000Z",
                "state": "closed",
                "policy_digest": "sha256:cli"
            },
            "sources": {
                "actions": "empty",
                "requests": "empty",
                "control": "empty"
            },
            "events": [],
            "dropped": 0
        }"#;
        fs::write(&input, json).unwrap();

        run(args(&[
            input.to_str().unwrap(),
            "--out",
            output.to_str().unwrap(),
        ]))
        .unwrap();

        let html = fs::read_to_string(&output).unwrap();
        assert!(html.contains("br_cli"));
        assert!(html.contains("<!DOCTYPE html>"));

        let _ = fs::remove_dir_all(&dir);
    }
}
