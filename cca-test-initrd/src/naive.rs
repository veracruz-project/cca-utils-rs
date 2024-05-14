use anyhow::{anyhow, Error, Result};
use nix::fcntl::{open, OFlag};
use nix::sys::stat::Mode;
use nix::unistd::{close, mkdir, read, write};

pub fn attestation(challenge: &[u8], _challenge_id: i32) -> Result<Vec<u8>, Error>{
    let chmod_0755: Mode = Mode::S_IRWXU | Mode::S_IRGRP | Mode::S_IXGRP |
        Mode::S_IROTH | Mode::S_IXOTH;
    let report = "/sys/kernel/config/tsm/report/report0";
    let inblob = format!("{report}/inblob");
    let outblob = format!("{report}/outblob");

    mkdir(report, chmod_0755).ok();
    info!("cca_test::attestation Created {}", report);

    let s = nix::sys::stat::stat(inblob.as_str());
    info!("cca_test::attestation {} {:?}", inblob, s);

    let mut c = challenge;
    match open(inblob.as_str(), OFlag::O_WRONLY, Mode::empty()) {
            Ok(f) => {
            while c.len() > 0 {
                match write(f, challenge) {
                    Ok(l) => {
                        (_, c) = c.split_at(l);
                    },
                    Err(err) => {
                        error!("cca_test::attestation writing to inblob! {}", err);
                        return Err(anyhow!(err));
                    },
                }
            }
            close(f)?;
        },
        Err(err) => {
            error!("cca_test::attestation opening inblob failed! {}", err);
            return Err(anyhow!(err));
        }
    }

    match open(outblob.as_str(), OFlag::empty(), Mode::empty()) {
        Ok(f) => {
            let mut blob = vec![];
            loop {
                let mut buf = [0u8; 256];
                match read(f, &mut buf) {
                    Ok(l) => {
                        if l == 0 {
                            break;
                        } else {
                            blob.extend(buf.split_at(l).0);
                        }
                    },
                    Err(err) => {
                        error!("cca_test::attestation from outblob! {}", err);
                        return Err(anyhow!(err));
                    },
                }
            }
            return Ok(blob);
        },
        Err(err) => {
            error!("cca_test::attestation opening outblob failed! {}", err);
            return Err(anyhow!(err));
        }
    }
}
