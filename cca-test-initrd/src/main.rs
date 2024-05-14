#[macro_use]
extern crate log;

#[cfg(not(feature="tsm_report"))]
mod naive;

use anyhow::{Error, Result};
use base64::prelude::*;
use nix::mount::{mount, MsFlags}; // MntFlags
use nix::sys::stat::Mode;
use nix::unistd::{mkdir};
#[cfg(feature="verify")]
use ccatoken::{store::MemoTrustAnchorStore, token};

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
    let token = naive::attestation(&challenge, 0).unwrap();

    #[cfg(feature="tsm_report")]
    let token = {
        let r = tsm_report::TsmReportPath::new(tsm_report::TsmReportProvider::Cca).unwrap();
        r.attestation_report(tsm_report::TsmReportData::Cca(challenge.to_vec())).unwrap()
    };

    info!("cca_test::attestation token is {} bytes long", token.len());
    let base64 = BASE64_STANDARD.encode(&token[0..(token.len() as usize)]);
    info!("cca_test::attestation token = {:x?}", base64);

    #[cfg(feature="verify")]
    {
        let ta_store: &str = r#"[
    {
        "pkey": {
            "crv": "P-384",
            "kty": "EC",
            "x": "IShnxS4rlQiwpCCpBWDzlNLfqiG911FP8akBr-fh94uxHU5m-Kijivp2r2oxxN6M",
            "y": "hM4tr8mWQli1P61xh3T0ViDREbF26DGOEYfbAjWjGNN7pZf-6A4OTHYqEryz6m7U"
        },
        "implementation-id": "7f454c4602010100000000000000000003003e00010000005058000000000000",
        "instance-id": "0107060504030201000f0e0d0c0b0a090817161514131211101f1e1d1c1b1a1918"
    }
]"#;

        let mut tas: MemoTrustAnchorStore = Default::default();
        match tas.load_json(&ta_store) {
            Ok(_) => {},
            Err(e) => {
                error!("Loading trust anchors: {}", e);
            }
        }
        let mut e: token::Evidence = token::Evidence::decode(&token).unwrap();
        match e.verify(&tas) {
            Ok(_) => {
                info!("Token verification succeeded");
            },
            Err(e) => {
                error!("Token verification failed: {}", e);
            }
        }
        let (platform_tvec, realm_tvec) = e.get_trust_vectors();

        info!(
            "platform trust vector: {}",
            serde_json::to_string_pretty(&platform_tvec).unwrap()
        );
        info!(
            "realm trust vector: {}",
            serde_json::to_string_pretty(&realm_tvec).unwrap()
        );
    }

    #[cfg(feature="verbose")]
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
