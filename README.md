# SentinelKit

Suite open source de **análise de segurança** com 4 módulos e um dashboard único, para apoiar segurança defensiva e boas práticas de desenvolvimento.

> Backend em **Fastify** (Node.js), frontend estático em HTML/JS puro, sem etapa de build.

**Site online:** https://marcos-scox.github.io/sentinelkit-security/


## Uso responsável

Use o SentinelKit **apenas** em sistemas, sites e arquivos que você possui ou tem **autorização por escrito** para testar. Acesso ou teste não autorizado de sistemas de terceiros pode configurar crime no Brasil (Lei 12.737/2012 e Marco Civil da Internet).

O SentinelKit faz **somente análise passiva** — lê configurações, metadados e conteúdo público. Ele **não explora** vulnerabilidades, não injeta payloads e não realiza ataques.

## Módulos

| Módulo | O que faz | Fonte |
|---|---|---|
| **Dependências** | Bibliotecas com CVEs conhecidas em manifestos npm/PyPI | API pública OSV.dev |
| **Web / Headers** | Headers de segurança, redirect HTTPS, cookies, arquivos expostos (.git, .env) | Requisições passivas |
| **Segredos** | Chaves de API, tokens e senhas em repos GitHub, texto ou arquivos | Padrões + entropia |
| **APK** | Análise estática Android: permissões, debuggable, HTTP, segredos hardcoded | Leitura do pacote |

Todos os módulos devolvem o mesmo formato: score 0-100, nota A-F e achados por severidade (critical/high/medium/low/info).

## Rodando localmente

    npm install
    npm start      # http://localhost:3000
    npm run dev    # com --watch
    npm test       # testes de fumaça (sem rede)

Abra http://localhost:3000 para o dashboard.

## Endpoints da API

- POST /api/scan/deps   — JSON {filename, content} ou multipart file
- POST /api/scan/web    — JSON {url, deepFiles?}
- POST /api/scan/secrets — JSON {repo} | {filename, content} ou multipart file
- POST /api/scan/apk    — multipart file (.apk)
- GET  /api/health

## Proteções embutidas

- Anti-SSRF: o módulo web recusa localhost, redes privadas (10/8, 192.168/16, 172.16/12) e o IP de metadata de nuvem 169.254.169.254. Para ambiente interno próprio, use ALLOW_PRIVATE_TARGETS=true.
- Rate limit de 30 req/min por IP.
- Segredos redigidos nos relatórios (nunca exibe a credencial inteira).
- Limites de tamanho de upload e de arquivos analisados.

## Publicação

O dashboard estático pode ser publicado no **GitHub Pages** a partir da pasta `public/`. O Pages não executa o backend Node; para habilitar as análises, hospede o backend em Render/Railway/Fly.io e defina `window.SENTINELKIT_API` antes de carregar `app.js` (ou use o mesmo domínio em um proxy).

## Deploy gratuito

Funciona em qualquer host Node. Tiers gratuitos: Render, Railway, Fly.io. Veja render.yaml.

## Persistência opcional (Supabase)

Para salvar histórico de scans, crie as tabelas de supabase/schema.sql e configure .env (veja .env.example). Sem isso, o SentinelKit funciona normalmente, só sem histórico.

## Roadmap

- [ ] Exportar relatório em PDF
- [ ] Histórico de scans no dashboard (Supabase)
- [ ] GitHub Action para rodar no CI
- [ ] Checagem de SSL/TLS detalhada

## Licença

MIT — veja LICENSE.
