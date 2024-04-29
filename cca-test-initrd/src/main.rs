#[macro_use]
extern crate log;

#[cfg(not(feature="tsm_report"))]
use anyhow::anyhow;
use anyhow::{Error, Result};
#[cfg(not(feature="tsm_report"))]
use nix::fcntl::{open, OFlag};
use nix::mount::{mount, MsFlags}; // MntFlags
use nix::sys::stat::Mode;
use nix::unistd::{mkdir};
#[cfg(not(feature="tsm_report"))]
use nix::unistd::{close, read, write};

#[cfg(not(feature="tsm_report"))]
fn attestation(challenge: &[u8], _challenge_id: i32) -> Result<Vec<u8>, Error>{
    let chmod_0755: Mode = Mode::S_IRWXU | Mode::S_IRGRP | Mode::S_IXGRP |
        Mode::S_IROTH | Mode::S_IXOTH;
    let report = "/sys/kernel/config/tsm/report/report0";
    let inblob = format!("{report}/inblob");
    let outblob = format!("{report}/outblob");

    mkdir(report, chmod_0755).ok();
    info!("cca_test::attestation Created {}", report);

    let s = nix::sys::stat::stat(inblob.as_str());
    info!("cca_test::attestation {} {:?}", inblob, s);

    let mut c = challenge.clone();
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
            info!("cca_test::attestation token is {} bytes long", blob.len());
            let base64 = base64::encode(&blob[0..(blob.len() as usize)]);
            info!("cca_test::attestation token = {:x?}", base64);
            return Ok(blob);
        },
        Err(err) => {
            error!("cca_test::attestation opening outblob failed! {}", err);
            return Err(anyhow!(err));
        }
    }
}

fn main() -> Result<()> {
    std::env::set_var("RUST_BACKTRACE", "full");

    // These cannot currently be constants
    let chmod_0555: Mode = Mode::S_IRUSR | Mode::S_IXUSR | Mode::S_IRGRP |
        Mode::S_IXGRP | Mode::S_IROTH | Mode::S_IXOTH;
    let chmod_0755: Mode = Mode::S_IRWXU | Mode::S_IRGRP | Mode::S_IXGRP |
        Mode::S_IROTH | Mode::S_IXOTH;
    let common_mnt_flags: MsFlags = MsFlags::MS_NODEV | MsFlags::MS_NOEXEC | MsFlags::MS_NOSUID;

    // /dev/urandom is required very early
    mkdir("/dev", chmod_0755).ok();
    let devtmpfs = Some("devtmpfs");
    mount(devtmpfs, "/dev", devtmpfs, MsFlags::MS_NOSUID, Some("mode=0755"))?;

    // Initialize logging
    env_logger::builder().parse_filters("debug").init();

    // Log retroactively :)
    info!("Starting init");
    debug!("Mounting /dev");

    debug!("Mounting /proc");
    mkdir("/proc", chmod_0555).ok();
    mount::<_, _, _, [u8]>(Some("proc"), "/proc", Some("proc"), common_mnt_flags, None)?;

    debug!("Mounting /sys");
    mkdir("/sys", chmod_0755).ok();
    mount::<_, _, _, [u8]>(Some("sysfs"), "/sys", Some("sysfs"), MsFlags::MS_NOSUID, None)?;

    debug!("Mounting /sys/kernel/config");
    mount::<_, _, _, [u8]>(Some("none"), "/sys/kernel/config", Some("configfs"),
        MsFlags::MS_NOSUID, None)?;

    let challenge = [0u8; 64];

    #[cfg(not(feature="tsm_report"))]
    let token = attestation(&challenge, 0).unwrap();

    #[cfg(feature="tsm_report")]
    let token = {
        let r = tsm_report::TsmReportPath::new(tsm_report::TsmReportProvider::Cca).unwrap();
        r.attestation_report(tsm_report::TsmReportData::Cca(challenge.to_vec())).unwrap()
    };

    if token.len() > 0 {
        let mut di = cbor_diag::parse_bytes(token).unwrap();

        if let cbor_diag::DataItem::Tag { tag: _, bitwidth: _, value } = di {
            di = *value;
        }

        if let cbor_diag::DataItem::Map { data, .. } = di {
            for item in data {
                if let cbor_diag::DataItem::ByteString(t) = item.1 {
                    let tok = cbor_diag::parse_bytes(t.data).unwrap();
                    if let cbor_diag::DataItem::Tag { tag: _, bitwidth: _, value } = tok {
                        if let cbor_diag::DataItem::Array { data, bitwidth: _ } = *value {
                            if let cbor_diag::DataItem::ByteString(cose) = data.get(2).unwrap() {
                                let v = &cose.data;
                                match cbor_diag::parse_bytes(v) {
                                    Ok(claims) => {
                                        info!("{}", claims.to_diag_pretty());
                                    },
                                    Err(e) =>{
                                        error!("Error parsing claims: {}", e);
                                    },
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    info!("Shutting down");
    return nix::sys::reboot::reboot(nix::sys::reboot::RebootMode::RB_POWER_OFF)
        .map(|_| {})
        .map_err(Error::from);
}
