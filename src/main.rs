mod theme;

use std::rc::Rc;

use bip85_core::bip85::{derive, Application};
use bip85_core::{seedqr, Xprv};
use slint_keyos_platform::app_ui;
use slint_keyos_platform::fs::{self, Location, OpenFlags};
use slint_keyos_platform::qrcode;
use slint_keyos_platform::slint::{Color, ComponentHandle, Image, VecModel};
use zeroize::Zeroize;

security::use_api!();

app_ui!("prime-bip85");

type Fs = fs::FileSystem<fs_permissions::FileSystemPermissions>;

const SAVE_DIR: &str = "/bip85";

/// (label, application, log tag, filename tag) for each Form.app-index row.
fn app_for_index(i: i32) -> Option<(&'static str, Application, &'static str)> {
    match i {
        0 => Some(("BIP-39 · 12 words", Application::Bip39 { words: 12 }, "words12")),
        1 => Some(("BIP-39 · 24 words", Application::Bip39 { words: 24 }, "words24")),
        2 => Some(("WIF (Bitcoin Core hdseed)", Application::Wif, "wif")),
        3 => Some(("XPRV (BIP-32 root)", Application::Xprv, "xprv")),
        4 => Some(("HEX · 32 bytes", Application::Hex { num_bytes: 32 }, "hex32")),
        _ => None,
    }
}

fn app_main(cx: AppContext, ui: AppWindow) {
    log_server::init_wait(env!("CARGO_CRATE_NAME")).unwrap();
    log::set_max_level(log::LevelFilter::Info);

    theme::init(&ui);

    let fs = cx.fs.clone(); // Arc<Fs>; &fs deref-coerces to &Fs below
    let ui_weak = ui.as_weak();

    // Remember what the result screen is showing so save() can write it
    // without re-deriving (and without parking the secret in more places
    // than the UI already does).
    let last: Rc<std::cell::RefCell<Option<LastDerivation>>> =
        Rc::new(std::cell::RefCell::new(None));

    {
        let ui_weak = ui_weak.clone();
        let last = last.clone();
        ui.global::<Callbacks>().on_derive(move || {
            let Some(ui) = ui_weak.upgrade() else { return };
            let form = ui.global::<Form>();
            let (app_index, child_index) = (form.get_app_index(), form.get_child_index());
            let Some((label, app, tag)) = app_for_index(app_index) else { return };

            ui.global::<Ui>().set_busy(true);
            let result = derive_from_device_seed(app, child_index as u32);
            ui.global::<Ui>().set_busy(false);

            match result {
                Ok(secret) => {
                    log::info!(
                        "cb: derive app={tag} index={child_index} ok path={}",
                        secret.path
                    );
                    let seedqr_digits = matches!(app, Application::Bip39 { .. })
                        .then(|| seedqr::seedqr_digits(&secret.entropy))
                        .and_then(Result::ok);
                    let qr_payload = seedqr_digits.as_deref().unwrap_or(&secret.display);

                    let d = ui.global::<Derived>();
                    d.set_app_label(format!("{label} · #{child_index}").into());
                    d.set_path(secret.path.as_str().into());
                    d.set_display(display_text(app, &secret.display).into());
                    d.set_has_seedqr(seedqr_digits.is_some());
                    d.set_show_qr(false);
                    d.set_qr(qr_image(qr_payload));
                    *last.borrow_mut() = Some(LastDerivation {
                        tag,
                        label,
                        index: child_index as u32,
                        path: secret.path.clone(),
                        display: secret.display.clone(),
                        seedqr: seedqr_digits,
                    });
                    ui.global::<Ui>().set_screen(1);
                }
                Err(e) => {
                    log::warn!("cb: derive app={tag} index={child_index} err={e}");
                    ui.global::<Ui>().set_error(e.into());
                }
            }
        });
    }

    {
        let ui_weak = ui_weak.clone();
        let fs = fs.clone();
        let last = last.clone();
        ui.global::<Callbacks>().on_save(move |location| {
            let Some(ui) = ui_weak.upgrade() else { return };
            let Some(d) = last.borrow().as_ref().map(LastDerivation::clone) else { return };
            let result = save_derivation(&fs, &d, location);
            match result {
                Ok(name) => {
                    log::info!(
                        "cb: save loc={} file={name} ok",
                        if location == 1 { "airlock" } else { "internal" }
                    );
                    ui.global::<Ui>().set_error("".into());
                }
                Err(e) => {
                    log::warn!("cb: save err={e}");
                    ui.global::<Ui>().set_error(e.into());
                    ui.global::<Ui>().set_screen(0);
                }
            }
        });
    }

    {
        let ui_weak = ui_weak.clone();
        let fs = fs.clone();
        ui.global::<Callbacks>().on_refresh_saved(move || {
            let Some(ui) = ui_weak.upgrade() else { return };
            let files = list_saved(&fs);
            log::info!("cb: refresh-saved count={}", files.len());
            let rows: Vec<SavedFile> = files
                .into_iter()
                .map(|(name, location)| SavedFile {
                    name: name.into(),
                    location: location.into(),
                })
                .collect();
            ui.global::<Saved>().set_files(Rc::new(VecModel::from(rows)).into());
        });
    }

    {
        let ui_weak = ui_weak.clone();
        let fs = fs.clone();
        ui.global::<Callbacks>().on_open_saved(move |name, location| {
            let Some(ui) = ui_weak.upgrade() else { return };
            let loc = parse_location(&location);
            match read_text(&fs, &format!("{SAVE_DIR}/{name}"), loc) {
                Ok(text) => {
                    log::info!("cb: open-saved file={name} loc={location} ok");
                    let s = ui.global::<Saved>();
                    s.set_viewer_name(name.clone());
                    s.set_viewer_location(location.clone());
                    s.set_viewer_text(text.into());
                    ui.global::<Ui>().set_screen(3);
                }
                Err(e) => log::warn!("cb: open-saved file={name} err={e}"),
            }
        });
    }

    {
        let ui_weak = ui_weak.clone();
        let fs = fs.clone();
        ui.global::<Callbacks>().on_delete_saved(move || {
            let Some(ui) = ui_weak.upgrade() else { return };
            let s = ui.global::<Saved>();
            let name = s.get_viewer_name();
            let loc = parse_location(&s.get_viewer_location());
            match fs.remove(format!("{SAVE_DIR}/{name}"), loc) {
                Ok(()) => log::info!("cb: delete-saved file={name} ok"),
                Err(e) => log::warn!("cb: delete-saved file={name} err={e:?}"),
            }
            // Refresh the list and return to the browser either way.
            let files = list_saved(&fs);
            let rows: Vec<SavedFile> = files
                .into_iter()
                .map(|(name, location)| SavedFile {
                    name: name.into(),
                    location: location.into(),
                })
                .collect();
            s.set_files(Rc::new(VecModel::from(rows)).into());
            ui.global::<Ui>().set_screen(2);
        });
    }

    ui.run().expect("UI running");
}

/// What save() writes; mirrors the result screen.
#[derive(Clone)]
struct LastDerivation {
    tag: &'static str,
    label: &'static str,
    index: u32,
    path: String,
    display: String,
    seedqr: Option<String>,
}

/// GetSeed → BIP39 root → BIP-85 child. The device seed entropy is zeroized
/// as soon as the root is built; the root and child zeroize on drop.
fn derive_from_device_seed(
    app: Application,
    index: u32,
) -> Result<bip85_core::DerivedSecret, String> {
    let seed = Security::default()
        .seed()
        .map_err(|_| "Seed unavailable — is the device set up and unlocked?".to_string())?
        .ok_or_else(|| "No wallet seed on this device yet".to_string())?;
    let mut entropy = seed.to_vec();
    // BIP-85 root = BIP32 root of the bare mnemonic (no passphrase); wallets
    // that derive from a passphrase-protected seed would use the passphrased
    // root instead, but GetSeed exposes only the base entropy.
    let root = Xprv::from_bip39_entropy(&entropy, "").map_err(|e| e.to_string())?;
    entropy.zeroize();
    derive(&root, app, index).map_err(|e| e.to_string())
}

/// Mnemonics read better numbered; everything else is a single token.
fn display_text(app: Application, display: &str) -> String {
    match app {
        Application::Bip39 { .. } => display
            .split(' ')
            .enumerate()
            .map(|(i, w)| format!("{}. {w}", i + 1))
            .collect::<Vec<_>>()
            .join("   "),
        _ => display.to_string(),
    }
}

fn qr_image(payload: &str) -> Image {
    qrcode::render(
        payload.as_bytes(),
        Color::from_rgb_u8(0, 0, 0),
        Color::from_rgb_u8(255, 255, 255),
    )
}

fn parse_location(s: &str) -> Location {
    if s == "Airlock" {
        Location::Airlock
    } else {
        Location::User
    }
}

fn save_derivation(fs: &Fs, d: &LastDerivation, location: i32) -> Result<String, String> {
    let loc = if location == 1 {
        ensure_airlock_mounted(fs)?;
        Location::Airlock
    } else {
        Location::User
    };
    if let Err(e) = fs.create_dir(SAVE_DIR, loc) {
        if !matches!(e, fs::Error::FileAlreadyExists) {
            return Err(err_msg(&e));
        }
    }
    let name = format!("bip85-{}-i{}.txt", d.tag, d.index);
    let path = format!("{SAVE_DIR}/{name}");
    if fs.open_file(path.as_str(), loc, OpenFlags::READ_ONLY).is_ok() {
        return Err(format!("{name} already exists"));
    }
    let mut text = format!(
        "BIP-85 derived secret\nApplication: {}\nPath: {}\nIndex: {}\n\n{}\n",
        d.label, d.path, d.index, d.display
    );
    if let Some(digits) = &d.seedqr {
        text.push_str(&format!("\nSeedQR: {digits}\n"));
    }
    fs.open_file(path.as_str(), loc, OpenFlags::CREATE)
        .and_then(|mut f| f.overwrite(text.as_bytes()))
        .map_err(|e| err_msg(&e))?;
    Ok(name)
}

fn list_saved(fs: &Fs) -> Vec<(String, &'static str)> {
    let mut out = Vec::new();
    for (loc, label) in [(Location::User, "Internal"), (Location::Airlock, "Airlock")] {
        // Airlock may simply not be mounted; skip quietly (mounting is the
        // save path's job — browsing should never format anything).
        if let Ok(dir) = fs.open_dir(SAVE_DIR, loc) {
            while let Ok(Some(entry)) = dir.next_entry() {
                if entry.is_file && entry.name.ends_with(".txt") {
                    out.push((entry.name, label));
                }
            }
        }
    }
    out.sort();
    out
}

fn read_text(fs: &Fs, path: &str, loc: Location) -> Result<String, String> {
    use std::io::Read;
    let mut file = fs.open_file(path, loc, OpenFlags::READ_ONLY).map_err(|e| err_msg(&e))?;
    let mut buf = Vec::new();
    file.read_to_end(&mut buf).map_err(|_| "Read failed".to_string())?;
    String::from_utf8(buf).map_err(|_| "Not a text file".to_string())
}

/// Lazy Airlock mount with format-on-failed-mount recovery (nothing mounts
/// Airlock in the hosted simulator; see paper-wallet NOTES.md).
fn ensure_airlock_mounted(fs: &Fs) -> Result<(), String> {
    let mut fs = fs.clone();
    if fs.mount_airlock().is_ok() {
        return Ok(());
    }
    log::warn!("airlock mount failed — formatting (no readable filesystem)");
    fs.format_airlock()
        .and_then(|_| fs.mount_airlock())
        .map_err(|e| format!("Airlock unavailable: {}", err_msg(&e)))
}

fn err_msg(e: &fs::Error) -> String {
    format!("{e:?}")
}
