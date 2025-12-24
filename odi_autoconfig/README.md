# ODI Autoconfig

Ferramenta desenvolvida em Rust projetada para automatizar a configuração de sticks XPON ONU da série **ODI DFP-34X** (e dispositivos Realtek compatíveis), facilitando o provisionamento na rede **Vivo Fibra**.

Ela remove a necessidade de configuração manual, copiando automaticamente o SLID (se disponível), detectando informações do dispositivo e configurando parâmetros OMCI e VLAN.

## Funcionalidades

- **Integração com Vivo Scraper**: Detecta automaticamente arquivos JSON gerados pelo `vivo_scraper` no diretório atual, na pasta do executável, ou no diretório adjacente (`../vivo_scraper/`) para preenchimento do SLID e Senha PLOAM.
- **Configuração Automática**:
  - **Login**: Acessa a interface web do stick (padrão `192.168.1.1`).
  - **GPON**: Configura SLID, LOID e Serial GPON.
  - **OMCI**: Define Vendor ID, Versões de Software e Hardware para emular o roteador original (Mitrastar/Askey).
- **Descoberta Inteligente de VLAN**:
  - Conecta-se via SSH ao stick.
  - Consulta a tabela MIB (`omcicli mib get 84`) para descobrir qual VLAN a OLT atribuiu.
  - Configura automaticamente a VLAN no modo Manual/PVID.
- **Backup**: Salva o estado atual e configurações extraídas em arquivos JSON locais para referência (`odi_device_status.json`, `odi_pon_status.json`, etc.).

## Como Usar

### Opção 1: Usando o Executável

1. **Preparação**:
   - Conecte seu computador à porta LAN do stick ODI (IP estático na faixa `192.168.1.x` pode ser necessário inicialmente se o DHCP não estiver ativo, mas o padrão do stick é 1.1).
   - (Opcional) Coloque o arquivo `.json` gerado pelo `mitrastar_scraper` na mesma pasta do executável.
2. **Executar**:
   - Execute o `odi_autoconfig.exe`.
   - Insira o usuário e senha do stick quando solicitado (padrão geralmente é `admin` / `admin`).
3. **Aguardar**:
   - A ferramenta exibirá o progresso no console. Ao final, se o sucesso for indicado, o stick estará configurado e (idealmente) conectado.

### Opção 2: Compilando do Código Fonte

1. **Pré-requisitos**: Certifique-se de ter [Rust e Cargo instalados](https://rustup.rs/).
2. **Compilar e Executar**:
   ```bash
   cargo run
   ```

## Checksum do Binário (v0.1.0)
SHA256: `D14E4E14F525E0C0B0CA9B44A72CDF91012DA2EB96E6ACB8A6A668056F5F7C3E`

## Licença

Este projeto está licenciado sob:

 * Apache License, Version 2.0
   ([LICENSE-APACHE](LICENSE-APACHE) ou http://www.apache.org/licenses/LICENSE-2.0)
 * MIT license
   ([LICENSE-MIT](LICENSE-MIT) ou http://opensource.org/licenses/MIT)

à sua escolha.
