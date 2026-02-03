from airflow import DAG
from airflow.operators.python import PythonOperator
from airflow.models import Variable
from datetime import datetime, timedelta, timezone
import requests
import time
import json
import re

def fetch_nvd_daily():
    from airflow.providers.postgres.hooks.postgres import PostgresHook
    pg_hook = PostgresHook(postgres_conn_id="postgres_vulnerability")
    api_key = Variable.get("NVD_API_KEY")
    # Removido barra final se existir para evitar erro na montagem da URL
    base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    headers = {"Accept": "application/json", "apiKey": api_key}

    # Limpeza rigorosa da data para evitar 404
    raw_last_run = Variable.get("NVD_LAST_RUN", default_var=(datetime.now(timezone.utc) - timedelta(days=1)).isoformat())
    # Garante que pegamos apenas a parte ISO sem lixo
    clean_last_run = raw_last_run.strip().replace('"', '').replace("'", "")
    start_date = datetime.fromisoformat(clean_last_run).astimezone(timezone.utc)
    end_date = datetime.now(timezone.utc)

    conn = pg_hook.get_conn()
    cur = conn.cursor()

    start_index = 0
    total_results = 1

    while start_index < total_results:
        # A API v2.0 exige este formato exato: YYYY-MM-DDTHH:MM:SS.SSS
        params = {
            "resultsPerPage": 2000,
            "startIndex": start_index,
            "lastModStartDate": start_date.strftime("%Y-%m-%dT%H:%M:%S.000"),
            "lastModEndDate": end_date.strftime("%Y-%m-%dT%H:%M:%S.000")
        }
        
        # O uso do params=params no requests cuida da codificação dos caracteres : e -
        response = requests.get(base_url, headers=headers, params=params, timeout=60)
        
        if response.status_code != 200:
            # Levantar exceção faz a task aparecer como FAILED para você ver no dashboard
            raise Exception(f"Erro na API NVD: {response.status_code} - URL tentada: {response.url}")
            
        data = response.json()
        total_results = data.get("totalResults", 0)
        vulnerabilities = data.get("vulnerabilities", [])

        for item in vulnerabilities:
            cve = item.get("cve", {})
            json_str = json.dumps(item)
            
            # Extração via Regex que validamos
            vendor, produto = "Desconhecido", "Desconhecido"
            match = re.search(r'cpe:2\.3:[oah]:([^:]+):([^:]+):', json_str)
            if match:
                vendor, produto = match.group(1).capitalize(), match.group(2)

            metrics = cve.get("metrics", {})
            cvss = next((metrics[v][0].get("cvssData", {}) for v in ["cvssMetricV40", "cvssMetricV31", "cvssMetricV30"] if metrics.get(v)), {})

            cur.execute("""
                INSERT INTO vulnerability.nvd_cves (
                    cve_id, vendor, base_score, severidade, 
                    complexidade_ataque, interacao_usuario, vetor_string_completo, json_original, data_ultima_modificacao
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                ON CONFLICT (cve_id) DO UPDATE SET
                    vendor = EXCLUDED.vendor,
                    base_score = EXCLUDED.base_score,
                    severidade = EXCLUDED.severidade,
                    complexidade_ataque = EXCLUDED.complexidade_ataque,
                    interacao_usuario = EXCLUDED.interacao_usuario,
                    vetor_string_completo = EXCLUDED.vetor_string_completo,
                    json_original = EXCLUDED.json_original,
                    data_ultima_modificacao = EXCLUDED.data_ultima_modificacao;
            """, (
                cve.get("id"), vendor, 
                cvss.get("baseScore"), cvss.get("baseSeverity"),
                cvss.get("attackComplexity"), cvss.get("userInteraction"),
                cvss.get("vectorString"), json_str, end_date
            ))
        
        conn.commit()
        start_index += 2000
        time.sleep(6)

    Variable.set("NVD_LAST_RUN", end_date.isoformat())
    cur.close(); conn.close()

with DAG(
    dag_id="nvd_daily_update",
    start_date=datetime(2026, 1, 1),
    schedule_interval="@daily",
    catchup=False
) as dag:
    PythonOperator(task_id="fetch_daily_cves", python_callable=fetch_nvd_daily)
