# Vivo Scraper

Ferramenta desenvolvida em Rust projetada para autenticar e extrair informações de dispositivos de roteadores Vivo (MitraStar), visando especificamente modelos como o GPT-2731GN2A4P.

## Funcionalidades

- **Autenticação Avançada**: Replica a lógica de login em JavaScript do lado do cliente do roteador, incluindo:
  - Extração dinâmica do ID de Sessão (`sid`).
  - Hash MD5 das credenciais (`password` + `:` + `sid`).
  - Tratamento de campos de formulário ocultos e estruturas específicas de requisição POST.
- **Navegação Robusta**: Lida automaticamente com:
  - Injeções de frame baseadas em JavaScript (`document.getElementsByName...`).
  - Redirecionamentos HTML padrão.
  - Navegação em frames aninhados para encontrar as páginas de conteúdo corretas.
- **Extração Inteligente de Dados**:
  - Analisa a página `/cgi-bin/instalador.cgi`.
  - Extrai detalhes do dispositivo (Fabricante, Modelo, Serial, MAC, etc.).
  - **Extração de SLID**: Decodifica a variável `gponPasswd` codificada em hexadecimal do JavaScript da página quando o campo de entrada HTML está oculto/vazio.
- **Saída JSON**: Salva os dados extraídos em um arquivo JSON nomeado com o modelo do roteador (ex: `GPT-2731GN2A4P.json`).

## Como Usar

### Opção 1: Usando o Executável (Recomendado)

1. **Baixar**: Baixe o arquivo `vivo_scraper-v0.1.0.zip` na seção de Releases do GitHub.
2. **Extrair**: Extraia o arquivo ZIP.
3. **Executar**: Abra o terminal na pasta onde extraiu o arquivo e execute:
   ```powershell
   .\mitrastar_scraper.exe
   ```

### Opção 2: Compilando do Código Fonte

1. **Pré-requisitos**: Certifique-se de ter [Rust e Cargo instalados](https://rustup.rs/).
2. **Compilar e Executar**:
   ```bash
   cargo run
   ```

### Saída Esperada
   A ferramenta registrará o progresso do login no console e salvará o arquivo JSON em caso de sucesso.
   ```
   Dados salvos com sucesso em: GPT-2731GN2A4P.json
   ```

## Configuração

Atualmente, o IP de destino e o usuário estão definidos diretamente (`hardcoded`) em `src/main.rs`:
- **URL**: `http://192.168.15.1`
- **Usuário**: `support`
- **Senha**: Solicitada interativamente durante a execução (geralmente encontrada na etiqueta atrás do aparelho).

## Checksum do Binário (v0.1.0)
SHA256: `2AD91CD5FF4EBE297F7CA543D428098B206840B43301C58AADCB88353DC56AD9`

## Licença

Este projeto está licenciado sob:

 * Apache License, Version 2.0
   ([LICENSE-APACHE](LICENSE-APACHE) ou http://www.apache.org/licenses/LICENSE-2.0)
 * MIT license
   ([LICENSE-MIT](LICENSE-MIT) ou http://opensource.org/licenses/MIT)

à sua escolha.
