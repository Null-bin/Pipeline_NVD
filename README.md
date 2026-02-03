# 🛡️ NVD Vulnerability Intelligence System

Sistema automatizado de ingestão, enriquecimento e roteamento de vulnerabilidades (CVEs) baseado na API 2.0 do NIST. Este projeto centraliza a gestão de falhas de segurança para equipes de TI e Cibersegurança.

## 📊 Panorama do Projeto
O sistema gerencia uma base de **330.421 registros** (1999-2026), processando dados em formato JSONB para extrair inteligência acionável.

### 🏗️ Arquitetura do Banco de Dados
A estrutura opera no **PostgreSQL** dentro do schema `vulnerability`, utilizando o usuário `airflow_sec` para garantir total independência operacional.

```mermaid
erDiagram
    NVD_CVES ||--o| VW_VULNERABILITY_INTELLIGENCE : "Analisa"
    ASSETS ||--o| DEFENDER_DETECTIONS : "Monitora"
    NVD_CVES ||--o| DEFENDER_DETECTIONS : "Vincula"
    
    NVD_CVES {
        varchar cve_id PK "Ex: CVE-2026-25211"
        text descricao "Resumo técnico da falha"
        numeric base_score "CVSS 3.x/4.0"
        jsonb json_original "Carga bruta do NIST"
        timestamp data_ultima_modificacao "Última atualização no NIST"
    }

    ASSETS {
        serial id PK
        varchar asset_id UK "Identificador Único"
        varchar endereco_ip "IP do Dispositivo"
        varchar servico_vinculado "Contexto de Negócio"
    }

