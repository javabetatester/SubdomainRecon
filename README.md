# SubdomainScanner

Uma ferramenta de descoberta e validação de subdomínios para um domínio-alvo, implementada em Python.

---

## Funcionalidades

- **Descoberta passiva**:
  - Extração de `SubjectAltName` em certificados SSL/TLS
  - Consulta ao `crt.sh` (JSON)
  - Dorks em Google, Yahoo e Bing
  - Arquivos do Wayback Machine (CDX API)
  - Zone transfer e enumeração DNS (NS, SOA, MX, TXT, CNAME, A, AAAA)
  - API do ThreatCrowd

- **Ferramentas externas** (opcional):
  - Subfinder
  - Amass
  - Assetfinder
  - Findomain
  - MassDNS
  - Anubis (curl + `jq`)
  - VirusTotal API (paginação)

- **Bruteforce** via wordlist customizável
- **Validação de portas TCP** (padrão: 80, 443, 8080, 8888)
- **Configurações**:
  - Timeout de requisições
  - Wordlist customizada
  - Habilitar ou desabilitar ferramentas externas

---

## Dependências

- Python 3.7+
- Bibliotecas Python:
  - `requests`
  - `dnspython`
  - `beautifulsoup4`
  - `tqdm`
  - `pyOpenSSL`
- Ferramentas de linha de comando (opcionais):
  - `subfinder`, `amass`, `assetfinder`, `findomain`, `massdns`, `jq`
  - `nmap` (para scanner de portas TCP)

---

## Instalação

1. Clone o repositório:
   ```bash
   git clone https://github.com/seu-usuario/subdomain-scanner.git
   cd subdomain-scanner
   ```
2. Instale as dependências Python:
   ```bash
   pip install -r requirements.txt
   ```
3. (Opcional) Instale as ferramentas externas e garanta que estejam no seu `PATH`.


4. Lembre-se de adcionar suas chaves de API do Virus Total, caso contrário você deixrá de coletar diversos sub-domínios.

---

## Uso

Execute o scanner via linha de comando:

```bash
python scanner.py <domínio> [opções]
```

### Opções principais

| Flag               | Descrição                                            |
|--------------------|------------------------------------------------------|
| `<domínio>`        | Domínio alvo (ex.: `example.com`)                    |
| `-w, --wordlist`   | Caminho para wordlist customizada                    |
| `-t, --threads`    | Threads para validação TCP (padrão: 10)              |
| `-to, --timeout`   | Timeout de requisição em segundos (padrão: 5)        |
| `--no-tools`       | Desabilita ferramentas externas de enumeração        |
| `-o, --output`     | Diretório de saída dos arquivos gerados (padrão: `.`)|

### Exemplos de uso

- **Scan padrão** com ferramentas externas:
  ```bash
  python scanner.py example.com
  ```

- **Scan sem ferramentas externas** e com wordlist própria:
  ```bash
  python scanner.py example.com -w wordlist.txt --no-tools
  ```

---

## Saída

- `<domínio>_subdomains.txt`: lista de subdomínios únicos encontrados.
- `<domínio>_ativos.txt`: subdomínios que responderam nas portas especificadas.

---

## Licença

MIT License

