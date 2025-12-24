use anyhow::{Context, Result};
use regex::Regex;
use reqwest::blocking::Client;
use serde::{Deserialize, Serialize};
use ssh2::Session;
use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::net::TcpStream;

#[derive(Debug, Deserialize)]
struct VivoDeviceInfo {
    #[serde(rename = "SLID")]
    slid: Option<String>,
}

#[derive(Debug, Serialize)]
struct DeviceStatus {
    #[serde(rename = "Device Name")]
    device_name: Option<String>,
    #[serde(rename = "Firmware Version")]
    firmware_version: Option<String>,
    #[serde(rename = "MAC Address")]
    mac_address: Option<String>,
    #[serde(rename = "Calculated MACKEY")]
    calculated_mackey: Option<String>,
}

#[derive(Debug, Serialize)]
struct PonStatus {
    #[serde(rename = "ONU State")]
    onu_state: Option<String>,
    #[serde(rename = "ONU ID")]
    onu_id: Option<String>,
    #[serde(rename = "LOID Status")]
    loid_status: Option<String>,
}

#[derive(Debug, Serialize)]
struct GponSettings {
    #[serde(rename = "LOID")]
    loid: Option<String>,
    #[serde(rename = "LOID Password")]
    loid_password: Option<String>,
    #[serde(rename = "PLOAM Format")]
    ploam_format: Option<String>,
    #[serde(rename = "PLOAM Password")]
    ploam_password: Option<String>,
    #[serde(rename = "GPON SN")]
    gpon_sn: Option<String>,
    #[serde(rename = "Vendor ID")]
    vendor_id: Option<String>,
    #[serde(rename = "software version 1")]
    software_version_1: Option<String>,
    #[serde(rename = "software version 2")]
    software_version_2: Option<String>,
    #[serde(rename = "OMCC version")]
    omcc_version: Option<String>,
    #[serde(rename = "Product Class")]
    product_class: Option<String>,
    #[serde(rename = "HW version")]
    hw_version: Option<String>,
    #[serde(rename = "OUI")]
    oui: Option<String>,
    #[serde(rename = "Device Serial Number")]
    device_serial_number: Option<String>,
    #[serde(rename = "MAC")]
    mac: Option<String>,
    #[serde(rename = "MACKEY")]
    mackey: Option<String>,
    #[serde(rename = "Fiber Reset")]
    fiber_reset: Option<String>,
}

fn main() -> Result<()> {
    let base_url = "http://192.168.1.1";
    let login_url = format!("{}/boaform/admin/formLogin", base_url);
    let target_url = format!("{}/gpon.asp", base_url);
    // Prompt for username
    print!("Digite o usuário do dispositivo (padrão admin): ");
    io::stdout().flush()?;
    let mut username_input = String::new();
    io::stdin().read_line(&mut username_input)?;
    let mut username = username_input.trim();

    if username.is_empty() {
        username = "admin";
        println!("Usando usuário padrão: admin");
    }

    // Prompt for password
    print!("Digite a senha do dispositivo (padrão admin): ");
    io::stdout().flush()?;
    let mut password_input = String::new();
    io::stdin().read_line(&mut password_input)?;
    let mut password = password_input.trim();

    if password.is_empty() {
        password = "admin";
        println!("Usando senha padrão: admin");
    }

    println!("Iniciando ODI Autoconfig...");

    // Try to load SLID from Vivo Scraper output
    let cached_slid = find_vivo_slid();
    if let Some(ref slid) = cached_slid {
        println!("Encontrado SLID do Vivo Scraper: {}", slid);
    } else {
        println!(
            "Aviso: Nenhum arquivo JSON do Vivo Scraper encontrado. O campo PLOAM Password não será preenchido automaticamente."
        );
    }

    let client = Client::builder()
        .cookie_store(true)
        .danger_accept_invalid_certs(true)
        .build()?;

    // Step 1: Hit the login page to initialize session/cookies
    println!("Acessando página de login para inicializar cookies...");
    let login_page_url = format!("{}/admin/login.asp", base_url);
    client.get(&login_page_url).send()?;

    // Step 2: Login
    println!("Tentando login...");
    // Assuming plain text based on empty setpass() in source.
    // If this fails, we might need MD5 challenge logic.
    let form_data = [
        ("username", username),
        ("password", password),
        ("save", "Login"),
        ("submit-url", "/admin/login.asp"),
    ];

    let res = client
        .post(&login_url)
        .form(&form_data)
        .send()
        .context("Falha ao enviar requisição de login")?;

    if !res.status().is_success() {
        return Err(anyhow::anyhow!("Login falhou com status: {}", res.status()));
    }

    // Check for login failure in response text (if redirected back to login)
    let body = res.text()?;
    if body.contains("user or password validation failed") || body.contains("login.asp") {
        println!("Aviso: O login pode ter falhado. Verifique as credenciais.");
    } else {
        println!("Login enviado com sucesso.");
    }

    // Step 3: Access Status Page first (BroadBand Device Webserver1 / status.asp)
    println!("Acessando Status Page ({}/admin/status.asp)", base_url);
    let status_res = client
        .get(&format!("{}/admin/status.asp", base_url))
        .send()?;
    let status_html = status_res.text()?;

    // Extract Status Info
    let mut status_info = extract_device_status(&status_html);

    // Calculate MACKEY if MAC is present
    if let Some(ref mac) = status_info.mac_address {
        let mackey = calculate_mackey(mac);
        println!("Calculated MACKEY (SSH approximation): {}", mackey);
        status_info.calculated_mackey = Some(mackey);
    }

    let status_json = serde_json::to_string_pretty(&status_info)?;
    println!("Status Info: {}", status_json);

    let status_filename = "odi_device_status.json";
    let mut status_file = File::create(status_filename)?;
    status_file.write_all(status_json.as_bytes())?;
    println!("Dados de status salvos em {}", status_filename);

    // Step 4: Access PON Status Page (/status_pon.asp)
    println!("Acessando PON Status Page ({}/status_pon.asp)", base_url);
    let pon_res = client.get(&format!("{}/status_pon.asp", base_url)).send()?;
    let pon_html = pon_res.text()?;

    let pon_info = extract_pon_status(&pon_html);
    let pon_json = serde_json::to_string_pretty(&pon_info)?;
    println!("PON Info: {}", pon_json);

    let pon_filename = "odi_pon_status.json";
    let mut pon_file = File::create(pon_filename)?;
    pon_file.write_all(pon_json.as_bytes())?;
    println!("Dados de PON salvos em {}", pon_filename);

    // Step 5: Access Settings Page
    println!("Acessando Settings ({})", target_url);
    let settings_res = client.get(&target_url).send()?;
    let settings_html = settings_res.text()?;

    // Debug: Save HTML to file
    let mut file = File::create("gpon_settings_debug.html")?;
    file.write_all(settings_html.as_bytes())?;
    println!("Página salva em gpon_settings_debug.html");

    // Step 6: Extract Data
    let info = extract_settings(&settings_html);
    let json_str = serde_json::to_string_pretty(&info)?;
    println!("{}", json_str);

    let output_filename = "odi_gpon_settings.json";
    let mut out_file = File::create(output_filename)?;
    out_file.write_all(json_str.as_bytes())?;
    println!("Dados salvos em {}", output_filename);

    let backup_filename = "previous.json";
    let mut backup_file = File::create(backup_filename)?;
    backup_file.write_all(json_str.as_bytes())?;
    println!("Backup salvo em {}", backup_filename);

    // Step 7: Configure GPON
    if let Some(slid) = cached_slid {
        if let Some(ref device_name) = status_info.device_name {
            println!("Iniciando configuração GPON...");
            configure_gpon(&client, base_url, &settings_html, &slid, &device_name)?;
        } else {
            println!("Erro: Device Name não encontrado, não é possível configurar GPON SN.");
        }
    } else {
        println!(
            "Aviso: SLID não encontrado (ou não detectado anteriormente), pulando configuração automática."
        );
    }

    // Step 8: Configure OMCI Information
    println!("Acessando Settings novamente para configurar OMCI info...");
    let settings_res = client.get(&target_url).send()?;
    let settings_html_2 = settings_res.text()?;

    configure_omci(&client, base_url, &settings_html_2, &status_info)?;

    // Step 9: Fetch OMCI VID via SSH
    println!("Iniciando conexão SSH para obter VID...");
    let vid = fetch_omci_vid_via_ssh("192.168.1.1", username, password).unwrap_or_else(|e| {
        println!("Erro na conexão SSH: {}. Usando VID padrão (10).", e);
        "10".to_string()
    });
    println!("VID extraído: {}", vid);

    // Step 10: Configure VLAN
    println!("Acessando VLAN.asp para configurar VID...");
    let vlan_url = format!("{}/vlan.asp", base_url);
    #[allow(unused)] // Use variable vlan_html later if needed
    let vlan_html = match client.get(&vlan_url).send() {
        Ok(res) => res.text().unwrap_or_default(),
        Err(e) => {
            println!("Erro ao acessar vlan.asp: {}", e);
            String::new()
        }
    };

    configure_vlan(&client, base_url, &vlan_html, &vid)?;

    // Append VLAN info to previous.json
    if let Ok(content) = fs::read_to_string("previous.json") {
        if let Ok(mut json) = serde_json::from_str::<serde_json::Value>(&content) {
            json["vlan_vid"] = serde_json::Value::String(vid.clone());
            json["vlan_mode"] = serde_json::Value::String("Manual/PVID".to_string());
            if let Ok(updated) = serde_json::to_string_pretty(&json) {
                let _ = fs::write("previous.json", updated);
                println!("Backup atualizado em previous.json com informações de VLAN.");
            }
        }
    }

    Ok(())
}

fn fetch_omci_vid_via_ssh(ip: &str, user: &str, pass: &str) -> Result<String> {
    println!("Tentando conexão SSH via ssh2 (standard port 22)...");

    let tcp = TcpStream::connect(format!("{}:22", ip)).context("Falha ao conectar via TCP")?;
    let mut sess = Session::new()?;
    sess.set_tcp_stream(tcp);
    sess.handshake().context("SSH handshake falhou")?;
    sess.userauth_password(user, pass)
        .context("SSH auth falhou")?;

    if !sess.authenticated() {
        return Err(anyhow::anyhow!("Autenticação SSH falhou"));
    }

    let mut channel = sess.channel_session()?;
    channel.exec("omcicli mib get 84")?;

    let mut s = String::new();
    channel.read_to_string(&mut s)?;
    channel.wait_close()?;

    println!("Saída SSH bruta:\n{}", s);

    let re = Regex::new(r"VID\s+(\d+)").unwrap();
    if let Some(cap) = re.captures(&s) {
        return Ok(cap[1].to_string());
    }

    Ok("10".to_string())
}

fn configure_vlan(
    client: &Client,
    base_url: &str,
    _html: &str, // Currently using hardcoded names
    vid: &str,
) -> Result<()> {
    let form_data = [
        ("vlan_cfg_type", "1"),  // Manual
        ("vlan_manu_mode", "1"), // PVID
        ("vlan_manu_tag_vid", vid),
        ("save", "Apply Changes"),
        ("submit-url", "/vlan.asp"),
    ];

    println!("Enviando configuração VLAN (VID: {})...", vid);
    let url = format!("{}/boaform/admin/formVlan", base_url);

    let res = client.post(&url).form(&form_data).send()?;

    if res.status().is_success() {
        println!(
            "Configuração VLAN enviada com sucesso! (Status: {})",
            res.status()
        );
    } else {
        println!(
            "Falha ao enviar configuração VLAN. Status: {}",
            res.status()
        );
    }

    Ok(())
}

fn configure_omci(
    client: &Client,
    base_url: &str,
    html: &str,
    status_info: &DeviceStatus,
) -> Result<()> {
    // Need: Device Name (for product class), MAC (for serial), MAC (lower), MACKEY
    let device_name = status_info.device_name.as_deref().unwrap_or("");
    let mac = status_info.mac_address.as_deref().unwrap_or("");
    let mackey = status_info.calculated_mackey.as_deref().unwrap_or("");

    // Formatting
    let clean_mac = mac.replace(|c: char| !c.is_ascii_hexdigit(), "");
    let hw_serial_no = clean_mac.to_uppercase();
    let mac_lower = clean_mac.to_lowercase();

    // 1. Extract Field Names (Dynamic fallback to hardcoded from prompt)
    let vendor_id_name =
        extract_input_name(html, "Vendor ID").unwrap_or("omci_vendor_id".to_string());
    let sw_ver1_name =
        extract_input_name(html, "software version 1").unwrap_or("omci_sw_ver1".to_string());
    let sw_ver2_name =
        extract_input_name(html, "software version 2").unwrap_or("omci_sw_ver2".to_string());
    let omcc_ver_name = extract_select_name(html, "OMCC version").unwrap_or("omcc_ver".to_string());
    let prod_class_name =
        extract_input_name(html, "Product Class").unwrap_or("cwmp_productclass".to_string());
    let hw_ver_name = extract_input_name(html, "HW version").unwrap_or("cwmp_hw_ver".to_string());
    let oui_name = extract_input_name(html, "OUI").unwrap_or("oui".to_string());
    let dev_serial_name =
        extract_input_name(html, "Device Serial Number").unwrap_or("hw_serial_no".to_string());
    // Note: Prompt calls it "MAC" but regex might match "MACKEY" first if not careful.
    // extract_input_name uses regex.escape(label). "MAC" matches "MAC". "MACKEY" matches "MACKEY".
    // If we search "MAC", we might find MACKEY's input if it comes first?
    // In HTML prompt: MAC is before MACKEY.
    let mac_name = extract_input_name(html, "MAC").unwrap_or("mac".to_string());
    let mackey_name = extract_input_name(html, "MACKEY").unwrap_or("mackey".to_string());

    // Fiber Reset is a radio. Name is likely same for both radios.
    // HTML: <input type="radio" value="0" name="fiberreset">
    // We can extract name from specific label "Fiber Reset:"
    let fiber_reset_name =
        extract_input_radio_name(html, "Fiber Reset:").unwrap_or("fiberreset".to_string());

    println!("Campos OMCI detectados:");
    println!("  Vendor ID Name: {}", vendor_id_name);
    println!("  SW Ver 1 Name: {}", sw_ver1_name);
    println!("  SW Ver 2 Name: {}", sw_ver2_name);
    println!("  OMCC Ver Name: {}", omcc_ver_name);
    println!("  Prod Class Name: {}", prod_class_name);
    println!("  HW Ver Name: {}", hw_ver_name);
    println!("  OUI Name: {}", oui_name);
    println!("  Dev Serial Name: {}", dev_serial_name);
    println!("  MAC Name: {}", mac_name);
    println!("  MACKEY Name: {}", mackey_name);
    println!("  Fiber Reset Name: {}", fiber_reset_name);

    // 2. Prepare Payload
    let form_data = [
        (vendor_id_name.as_str(), "MSTC"),
        (sw_ver1_name.as_str(), "GG-11000-C003"),
        (sw_ver2_name.as_str(), "GG-11000-C003"),
        (omcc_ver_name.as_str(), "128"), // 0x80
        (prod_class_name.as_str(), device_name),
        (hw_ver_name.as_str(), "GG-GAPL100v02"),
        (oui_name.as_str(), "111111"),
        (dev_serial_name.as_str(), hw_serial_no.as_str()),
        (mac_name.as_str(), mac_lower.as_str()),
        (mackey_name.as_str(), mackey),
        (fiber_reset_name.as_str(), "1"), // Enable
        ("apply", "Apply Changes"),
        ("submit-url", "/gpon.asp"), // As per prompt hidden value
    ];

    println!("Enviando configuração OMCI...");
    let url = format!("{}/boaform/admin/formOmciInfo", base_url);

    let res = client.post(&url).form(&form_data).send()?;

    if res.status().is_success() {
        println!(
            "Configuração OMCI enviada com sucesso! (Status: {})",
            res.status()
        );
    } else {
        println!(
            "Falha ao enviar configuração OMCI. Status: {}",
            res.status()
        );
    }

    Ok(())
}

fn configure_gpon(
    client: &Client,
    base_url: &str,
    html: &str,
    slid: &str,
    device_name: &str,
) -> Result<()> {
    // 1. Extract Field Names
    let loid_name = extract_input_name(html, "LOID:").context("Campo LOID não encontrado")?;
    let loid_pass_name =
        extract_input_name(html, "LOID Password:").context("Campo LOID Password não encontrado")?;
    let ploam_fmt_name =
        extract_select_name(html, "PLOAM Format:").context("Campo PLOAM Format não encontrado")?;
    let ploam_pass_name = extract_input_name(html, "PLOAM Password:")
        .context("Campo PLOAM Password não encontrado")?;
    let gpon_sn_name =
        extract_input_name(html, "GPON SN:").context("Campo GPON SN não encontrado")?;

    // 2. Extract PLOAM Format Value (2nd option)
    let ploam_fmt_val =
        extract_second_option_value(html, "PLOAM Format:").unwrap_or_else(|| "1".to_string()); // Fallback to "1" (ASCII commonly)

    println!("Campos detectados:");
    println!("  LOID Name: {}", loid_name);
    println!("  LOID Pass Name: {}", loid_pass_name);
    println!(
        "  PLOAM Format Name: {}, Value: {}",
        ploam_fmt_name, ploam_fmt_val
    );
    println!("  PLOAM Pass Name: {}", ploam_pass_name);
    println!("  GPON SN Name: {}", gpon_sn_name);

    // 3. Prepare Payload
    let form_data = [
        (loid_name.as_str(), ""),
        (loid_pass_name.as_str(), ""),
        (ploam_fmt_name.as_str(), ploam_fmt_val.as_str()),
        (ploam_pass_name.as_str(), slid),
        (gpon_sn_name.as_str(), device_name),
        ("apply", "Apply Changes"),
        ("submit-url", "/gpon.asp"), // Usually required by BOA
    ];

    println!("Enviando configuração...");
    let url = format!("{}/boaform/admin/formgponConf", base_url);

    let res = client.post(&url).form(&form_data).send()?;

    if res.status().is_success() {
        println!(
            "Configuração enviada com sucesso! (Status: {})",
            res.status()
        );
    } else {
        println!("Falha ao enviar configuração. Status: {}", res.status());
    }

    Ok(())
}

fn extract_input_name(html: &str, label: &str) -> Option<String> {
    let label_esc = regex::escape(label);
    let re = Regex::new(&format!(
        r"(?is){}.*?<input[^>]*name=['\x22](.*?)['\x22]",
        label_esc
    ))
    .ok()?;
    re.captures(html).map(|c| c[1].to_string())
}

fn extract_select_name(html: &str, label: &str) -> Option<String> {
    let label_esc = regex::escape(label);
    let re = Regex::new(&format!(
        r"(?is){}.*?<select[^>]*name=['\x22](.*?)['\x22]",
        label_esc
    ))
    .ok()?;
    re.captures(html).map(|c| c[1].to_string())
}

fn extract_input_radio_name(html: &str, label: &str) -> Option<String> {
    let label_esc = regex::escape(label);
    // Label ... <input type="radio" ... name="NAME" ...>
    // Just find the name of the radio button near the label
    let re = Regex::new(&format!(
        r"(?is){}.*?<input[^>]*type=['\x22]radio['\x22][^>]*name=['\x22](.*?)['\x22]",
        label_esc
    ))
    .ok()?;
    re.captures(html).map(|c| c[1].to_string())
}

fn extract_second_option_value(html: &str, label: &str) -> Option<String> {
    let label_esc = regex::escape(label);
    // Find the select, then find options inside
    // This is getting complex for regex.
    // Try to find the block
    let select_re = Regex::new(&format!(
        r"(?is){}.*?<select[^>]*>(.*?)</select>",
        label_esc
    ))
    .ok()?;

    if let Some(cap) = select_re.captures(html) {
        let options_block = &cap[1];
        // Find all value="..."
        let val_re = Regex::new(r"(?i)value=['\x22](.*?)['\x22]").ok()?;
        let values: Vec<String> = val_re
            .captures_iter(options_block)
            .map(|c| c[1].to_string())
            .collect();

        if values.len() >= 2 {
            return Some(values[1].clone());
        }
    }
    None
}

fn extract_settings(html: &str) -> GponSettings {
    let find_val = |label: &str| -> Option<String> {
        let label_esc = regex::escape(label);

        // Strategy: We define a "search window" regex that starts at the Label and looks for the nearest form element.
        // We prioritize INPUT over SELECT if both appear, but generally they don't overlap for the same label.

        // 1. Try Input: Label ... <input ... value="...">
        // We restrict the lookahead to avoid jumping over other unrelated labels if possible,
        // but since we don't know the next label, we rely on 'lazy' matching .*?

        let input_re = Regex::new(&format!(
            r"(?is){}.*?<input[^>]*value=['\x22](.*?)['\x22]",
            label_esc
        ))
        .ok()?;

        // 2. Try Select: Label ... <select ...> ... <option selected value="..."> or <option value="..."> ... (if we parse HTML properly)
        // Regex for select is harder because 'selected' attribute denotes the value.
        // Look for: Label ... <select ...> ... <option ... selected ...>Text</option> OR <option ... value="val" ... selected>

        let select_re = Regex::new(&format!(
            r"(?is){}.*?<select[^>]*>.*?<option[^>]*value=['\x22](.*?)['\x22][^>]*selected",
            label_esc
        ))
        .ok()?;

        // We run both and take the one that appears earlier in the string?
        // Actually, matching from the specific label gives us a position.

        let input_match = input_re.captures(html);
        let select_match = select_re.captures(html);

        match (input_match, select_match) {
            (Some(im), Some(sm)) => {
                // Return the one whose match starts earlier?
                // Using .get(0).start()
                if im.get(0).unwrap().start() < sm.get(0).unwrap().start() {
                    Some(im[1].to_string())
                } else {
                    Some(sm[1].to_string())
                }
            }
            (Some(im), None) => Some(im[1].to_string()),
            (None, Some(sm)) => Some(sm[1].to_string()),
            (None, None) => None,
        }
    };

    GponSettings {
        loid: find_val("LOID:"),
        loid_password: find_val("LOID Password:"),
        ploam_format: find_val("PLOAM Format:"), // Might be select
        ploam_password: find_val("PLOAM Password:"),
        gpon_sn: find_val("GPON SN:"),
        vendor_id: find_val("Vendor ID"),
        software_version_1: find_val("software version 1"),
        software_version_2: find_val("software version 2"),
        omcc_version: find_val("OMCC version"), // Might be select
        product_class: find_val("Product Class"),
        hw_version: find_val("HW version"),
        oui: find_val("OUI"),
        device_serial_number: find_val("Device Serial Number"),
        mac: find_val("MAC"),
        mackey: find_val("MACKEY"),
        fiber_reset: {
            // Special regex for radio buttons (Fiber Reset)
            // Look for checked radio
            let escaped_label = regex::escape("Fiber Reset:");
            // Pattern: Label ... <input ... type="radio" ... checked ... value="VAL"> OR <input ... checked ... value="VAL">
            // But value might be "1" or "0". Text might be "Enable"/"Disable".
            // Let's just try to find the label associated with the checked radio if possible,
            // OR just find the value of the checks input.
            let radio_re = Regex::new(&format!(
                r"(?is){}.*?<input[^>]*type=['\x22]radio['\x22][^>]*checked[^>]*value=['\x22](.*?)['\x22]",
                escaped_label
            )).ok();

            if let Some(re) = radio_re {
                re.captures(html).map(|c| c[1].to_string())
            } else {
                None
            }
        },
    }
}

fn find_vivo_slid() -> Option<String> {
    // Look for json files in current dir, ../mitrastar_scraper/, and executable dir
    let mut search_paths = vec![
        std::path::PathBuf::from("."),
        std::path::PathBuf::from("../mitrastar_scraper/"),
    ];

    if let Ok(exe_path) = std::env::current_exe() {
        if let Some(exe_dir) = exe_path.parent() {
            search_paths.push(exe_dir.to_path_buf());
        }
    }

    for dir in search_paths {
        if let Ok(entries) = fs::read_dir(dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if let Some(ext) = path.extension() {
                    if ext == "json" {
                        // Parse it
                        if let Ok(file) = File::open(&path) {
                            if let Ok(info) = serde_json::from_reader::<_, VivoDeviceInfo>(file) {
                                if let Some(slid) = info.slid {
                                    if !slid.is_empty() {
                                        return Some(slid);
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    None
}

fn extract_device_status(html: &str) -> DeviceStatus {
    let find_val = |label: &str| -> Option<String> {
        let label_esc = regex::escape(label);
        // Pattern: <b>Label</b> ... <td ...><font ...>VALUE</font></td>
        // Use (?s) for dot matches newline
        let re = Regex::new(&format!(
            r"(?is)<b>{}<\/b>.*?<td[^>]*>.*?<font[^>]*>(.*?)<\/font>",
            label_esc
        ))
        .ok()?;

        if let Some(cap) = re.captures(html) {
            return Some(cap[1].trim().to_string());
        }
        None
    };

    DeviceStatus {
        device_name: find_val("Device Name"),
        firmware_version: find_val("Firmware Version"),
        mac_address: find_val("MAC Address"),
        calculated_mackey: None,
    }
}

fn extract_pon_status(html: &str) -> PonStatus {
    let find_val = |label: &str| -> Option<String> {
        let label_esc = regex::escape(label);
        // Pattern similar to device status: <b>Label</b> ... <td ...><font ...>VALUE</font></td>
        // But in the sample html provided for PON, the label is inside a <font> inside a <td>:
        // <td width="30%"><font size="2"><b>ONU State</b></font></td><td width="70%"><font size="2">O5</font></td>

        let re = Regex::new(&format!(
            r"(?is)<b>{}<\/b>.*?<td[^>]*>.*?<font[^>]*>(.*?)<\/font>",
            label_esc
        ))
        .ok()?;

        if let Some(cap) = re.captures(html) {
            // The font tag content might be the value directly.
            // In the second file, it is <font size="2">O5</font> inside the NEXT td.
            // Wait, my regex above:
            // <b>ONU State</b> is matched.
            // .*? eats the closing </font></td> of the label cell.
            // <td[^>]*> matches opening of value cell.
            // .*?<font[^>]*> matches font tag in value cell.
            // (.*?) captures value.
            // <\/font> matches closing font.
            // This logic holds for "BroadBand Device Webserver2_files/status.html" as seen:
            // <tr bgcolor="#DDDDDD"><td width="30%"><font size="2"><b>ONU State</b></font></td><td width="70%"><font size="2">O5</font></td> </tr>
            return Some(cap[1].trim().to_string());
        }
        None
    };

    PonStatus {
        onu_state: find_val("ONU State"),
        onu_id: find_val("ONU ID"),
        loid_status: find_val("LOID Status"),
    }
}

fn calculate_mackey(mac: &str) -> String {
    // Logic: echo -n "hsgq1.9aDEVICESERIALNUMBER" | md5sum
    // DEVICESERIALNUMBER is mac address (uppercase)

    // 1. Clean MAC: remove colons, dashes, etc.
    let clean_mac = mac
        .replace(|c: char| !c.is_ascii_hexdigit(), "")
        .to_uppercase();

    // 2. Construct string
    let input = format!("hsgq1.9a{}", clean_mac);

    // 3. MD5
    let digest = md5::compute(input.as_bytes());
    format!("{:x}", digest)
}
