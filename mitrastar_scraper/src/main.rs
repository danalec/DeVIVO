use anyhow::{Context, Result};
use regex::Regex;
use reqwest::Client;
use scraper::{Html, Selector};
use serde::Serialize;
use std::collections::HashMap;

#[derive(Debug, Serialize)]
struct DeviceInfo {
    #[serde(rename = "Fabricante")]
    fabricante: Option<String>,
    #[serde(rename = "Modelo")]
    modelo: Option<String>,
    #[serde(rename = "Versão do Software")]
    software_version: Option<String>,
    #[serde(rename = "Versão do Hardware")]
    hardware_version: Option<String>,
    #[serde(rename = "Número de Série")]
    serial_number: Option<String>,
    #[serde(rename = "GPON Número de Série")]
    gpon_serial_number: Option<String>,
    #[serde(rename = "Endereço MAC da WAN")]
    wan_mac: Option<String>,
    #[serde(rename = "Endereço MAC da LAN")]
    lan_mac: Option<String>,
    #[serde(rename = "SLID")]
    slid: Option<String>,
}

#[tokio::main]
async fn main() -> Result<()> {
    // Configuration
    let base_url = "http://192.168.15.1";
    let start_url = format!("{}/instalador", base_url);
    use std::io::{self, Write};

    // Prompt for username
    print!("Digite o usuário do roteador (padrão 'support', ou 'admin' etc.): ");
    io::stdout().flush()?;
    let mut username_input = String::new();
    io::stdin().read_line(&mut username_input)?;
    let mut username = username_input.trim();

    if username.is_empty() {
        username = "support";
        println!("Usando usuário padrão: support");
    }
    let password = rpassword::prompt_password("Digite a senha do roteador: ")?;

    println!("Iniciando Vivo Scraper...");

    // Initialize Client with Cookie Store and ignoring invalid certs (common on routers)
    let client = Client::builder()
        .user_agent("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36")
        .cookie_store(true)
        .danger_accept_invalid_certs(true)
        .build()?;

    // Step 1: Access the entry page and find the actual content (handling frames/redirects)
    println!("Acessando ponto de entrada: {}", start_url);
    let (page_url, html) = find_content_page(&client, &start_url).await?;
    println!("Conteúdo encontrado em: {}", page_url);

    // Step 2: Parse form
    println!("Analisando formulário de login...");

    // Extract SID from JavaScript
    let sid_re = Regex::new(r"var\s+sid\s*=\s*'([^']+)'").unwrap();
    let sid = sid_re
        .captures(&html)
        .context("Could not find 'sid' token in login page JavaScript")?
        .get(1)
        .unwrap()
        .as_str();
    println!("ID da Sessão encontrado (sid): {}", sid);

    let document = Html::parse_document(&html);
    let form_selector =
        Selector::parse("form").map_err(|e| anyhow::anyhow!("Selector error: {:?}", e))?;

    // Find the form - usually the first one or one with password field
    let form = document
        .select(&form_selector)
        .find(|f| f.inner_html().contains("password") || f.inner_html().contains("LoginPassword"))
        .or_else(|| document.select(&form_selector).next())
        .context(format!(
            "Não foi possível encontrar nenhum formulário de login na página: {}",
            page_url
        ))?;

    // Determine Action URL
    let action_attr = form.value().attr("action").unwrap_or("");
    let action_url = if action_attr.is_empty() {
        println!("Info: Ação do formulário vazia. Postando para URL atual.");
        page_url.clone()
    } else if action_attr.starts_with("http") {
        action_attr.to_string()
    } else {
        // Handle relative path (ensure leading slash logic)
        let base = reqwest::Url::parse(&page_url)?;
        let joined = base.join(action_attr)?;
        joined.to_string()
    };

    println!("URL de Ação de Login Identificada: {}", action_url);

    // Extract hidden fields - include buttons and selects
    let input_selector = Selector::parse("input, select, button").unwrap();
    let mut form_data = HashMap::new();

    for input in form.select(&input_selector) {
        let name = input.value().attr("name").unwrap_or("");
        let value = input.value().attr("value").unwrap_or("");
        let type_attr = input.value().attr("type").unwrap_or("");

        // Skip buttons that are not submits (optional refinement)
        if input.value().name() == "button" && type_attr != "submit" && !type_attr.is_empty() {
            continue;
        }

        if !name.is_empty() {
            form_data.insert(name.to_string(), value.to_string());
        }
    }

    // Prepare credentials payload matching the JS logic:
    // var passwd = hex_md5((document.passWarning.LoginPassword.value)+":"+sid);
    // Note: The original generic implementation added plain password. We must override/remove that if it was auto-added,
    // but here we are constructing it fresh.

    let raw_auth_string = format!("{}:{}", password, sid);
    let auth_digest = md5::compute(raw_auth_string.as_bytes());
    let auth_hash = format!("{:x}", auth_digest);
    println!("Hash de Autenticação Calculado: {}", auth_hash);

    form_data.insert("Loginuser".to_string(), username.to_string());
    form_data.insert("LoginPasswordValue".to_string(), auth_hash);
    form_data.insert("acceptLoginIndex".to_string(), "1".to_string());

    // Explicitly remove LoginPassword if it was scraped from the form, as the JS logic doesn't send it plain.
    form_data.remove("LoginPassword");

    // println!("Form Data to be sent: {:?}", form_data);
    println!("Tentando login...");

    // Step 3: Perform Login with Referer
    let login_res = client
        .post(&action_url)
        .header("Referer", &page_url)
        .form(&form_data)
        .send()
        .await?;

    if !login_res.status().is_success() {
        return Err(anyhow::anyhow!(
            "Falha na requisição de login: {}",
            login_res.status()
        ));
    }

    // Inspect Login Response
    let login_raw = login_res.text().await?;
    if login_raw.contains("inválida") || login_raw.contains("Invalid") || login_raw.contains("fail")
    {
        println!("Aviso: Resposta do login indica falha.");
    }

    // Step 4: Access the target data page
    let target_url = format!("{}/cgi-bin/instalador.cgi", base_url);
    println!("Buscando informações do equipamento em: {}", target_url);

    let data_res = client.get(&target_url).send().await?;
    // Note: Removed duplicate line 164 which was present in previous view

    let data_html = data_res.text().await?;
    if let Err(e) = std::fs::write("debug_data_page.html", &data_html) {
        println!("Aviso: Falha ao gravar debug_data_page.html: {:?}", e);
    } else {
        println!("Página HTML de dados salva em 'debug_data_page.html'");
    }

    // Step 5: Parse device information
    println!("Tamanho da página de dados: {}", data_html.len());
    if data_html.len() < 1000 {
        println!("Trecho do conteúdo da página: {}", data_html);
    }

    // Check if we were redirected to login
    if data_html.contains("LoginPassword") || data_html.contains("basefrm") {
        println!(
            "Aviso: A página de dados parece ser uma página de login ou frameset. A autenticação pode ter falhado."
        );
    }

    let info = extract_device_info(&data_html);

    // Output JSON
    let json_str = serde_json::to_string_pretty(&info)?;

    // Determine filename from Model, fallback to "device_info.json"
    let filename = info.modelo.as_deref().unwrap_or("device_info");
    // Simple sanitization to ensure valid filename (replace invalid chars)
    let safe_filename = filename.replace(|c: char| !c.is_alphanumeric() && c != '-', "_");
    let file_path = format!("{}.json", safe_filename);

    std::fs::write(&file_path, &json_str)?;
    println!("\nDados salvos com sucesso em: {}", file_path);

    Ok(())
}

// Helper to look for frames or redirects if the initial page is not the form
async fn find_content_page(client: &Client, start_url: &str) -> Result<(String, String)> {
    let mut current_url = start_url.to_string();
    let mut visited = std::collections::HashSet::new();

    for _ in 0..5 {
        // Max depth 5
        if visited.contains(&current_url) {
            break;
        }
        visited.insert(current_url.clone());

        let res = client.get(&current_url).send().await?;
        let final_url = res.url().to_string(); // In case of HTTP redirect
        let html = res.text().await?;

        // 1. Check for standard login form
        let document = Html::parse_document(&html);
        let form_selector = Selector::parse("form").unwrap();
        if document.select(&form_selector).next().is_some() {
            return Ok((final_url, html));
        }

        // 2. Check for Specific Frame Injection via JS (as seen in user example)
        let js_frame_re = Regex::new(
            r#"getElementsByName\s*\(\s*['"]basefrm['"]\s*\)\[0\]\.src\s*=\s*['"]([^'"]+)['"]"#,
        )
        .unwrap();
        if let Some(cap) = js_frame_re.captures(&html) {
            let target = &cap[1];
            println!("Encontrada injeção de frame JS apontando para: {}", target);
            let base = reqwest::Url::parse(&final_url)?;
            let next_url = base.join(target)?.to_string();
            current_url = next_url;
            continue;
        }

        // 3. Check for Frames (prioritize 'basefrm')
        let frame_selector = Selector::parse("frame, iframe").unwrap();
        let frames: Vec<_> = document.select(&frame_selector).collect();

        let target_frame = frames
            .iter()
            .find(|f| f.value().attr("name") == Some("basefrm"))
            .or_else(|| frames.first()); // Fallback to first if no basefrm

        if let Some(frame) = target_frame {
            if let Some(src) = frame.value().attr("src") {
                if !src.is_empty() {
                    println!("Encontrado frame apontando para: {}", src);
                    let base = reqwest::Url::parse(&final_url)?;
                    let next_url = base.join(src)?.to_string();
                    current_url = next_url;
                    continue;
                }
            }
        }

        // 4. Check for JS redirect (simple regex)
        let output = html.clone();
        if output.contains("location") {
            let re =
                Regex::new(r#"(?:window|self|top)\.location(?:\.href)?\s*=\s*['"]([^'"]+)['"]"#)
                    .unwrap();
            if let Some(cap) = re.captures(&html) {
                let target = &cap[1];
                println!("Encontrado redirecionamento JS para: {}", target);
                let base = reqwest::Url::parse(&final_url)?;
                let next_url = base.join(target)?.to_string();
                current_url = next_url;
                continue;
            }
        }

        // If no form, no frame, no redirect found, return what we have (might fail later)
        return Ok((final_url, html));
    }

    Err(anyhow::anyhow!(
        "Muitos redirecionamentos ou frames sem encontrar um formulário"
    ))
}

fn extract_device_info(html: &str) -> DeviceInfo {
    // Strategy: Convert HTML to pure text to remove tags, then regex search the text.
    let fragment = Html::parse_fragment(html);
    let text = fragment.root_element().text().collect::<Vec<_>>().join(" ");

    // Debug: Print a snippet of the text to see what we are working with
    // Debug: Print a snippet of the text to see what we are working with
    // if text.len() > 500 {
    //    println!("Extracted Text Snippet: {}...", &text[..500]);
    // } else {
    //     println!("Extracted Text: {}", text);
    // }

    // Helper to regex search in text
    let find_val = |keys: &[&str]| -> Option<String> {
        for key in keys {
            // Updated regex: stop at newline, tab, <, or ;
            let pattern_str = format!(r"(?i){}\s*[:]\s*([^\t\r\n<;]+)", regex::escape(key));
            if let Ok(re) = Regex::new(&pattern_str) {
                if let Some(cap) = re.captures(&text) {
                    let val = cap[1].trim();
                    if !val.is_empty() {
                        return Some(val.to_string());
                    }
                }
            }
        }
        None
    };

    // 1. Try to extract SLID from JS variable 'gponPasswd' (Hex encoded)
    let mut slid = None;
    let js_slid_re = Regex::new(r#"var\s+gponPasswd\s*=\s*"([^"]+)""#).unwrap();
    if let Some(cap) = js_slid_re.captures(html) {
        let hex_val = &cap[1];
        if !hex_val.is_empty() {
            // println!("Found parsed JS SLID (hex): {}", hex_val);
            // Decode Hex to String

            let mut bytes = Vec::new();
            for i in (0..hex_val.len()).step_by(2) {
                if i + 2 <= hex_val.len() {
                    if let Ok(b) = u8::from_str_radix(&hex_val[i..i + 2], 16) {
                        bytes.push(b);
                    }
                }
            }
            let decoded = String::from_utf8_lossy(&bytes).to_string();
            // println!("Decoded SLID: {}", decoded);
            slid = Some(decoded);
        }
    }

    // 2. Fallback to scraping text if JS extraction failed
    if slid.is_none() {
        if let Some(mut val) = find_val(&["Código SLID", "SLID"]) {
            if val.contains("PERFIL") {
                val = val.replace("PERFIL", "").trim().to_string();
            }
            if !val.is_empty() {
                slid = Some(val);
            }
        }
    }

    DeviceInfo {
        fabricante: find_val(&["Fabricante"]),
        modelo: find_val(&["Modelo"]),
        software_version: find_val(&["Versão do Software"]),
        hardware_version: find_val(&["Versão do Hardware"]),
        serial_number: find_val(&["Número de Série", "Número de Série (Serial Number)"]),
        gpon_serial_number: find_val(&["GPON Número de Série"]),
        wan_mac: find_val(&["Endereço MAC da WAN"]),
        lan_mac: find_val(&["Endereço MAC da LAN"]),
        slid,
    }
}
