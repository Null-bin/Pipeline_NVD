import requests
import time
import json
import re
from datetime import datetime, timedelta, timezone
from airflow import DAG
from airflow.operators.python import PythonOperator
from airflow.models import Variable

def fetch_nvd_incremental():
    from airflow.providers.postgres.hooks.postgres import PostgresHook
    pg_hook = PostgresHook(postgres_conn_id="postgres_vulnerability")
    api_key = Variable.get("NVD_API_KEY")
    base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    headers = {"Accept": "application/json", "apiKey": api_key}

    # Certifique-se de que NVD_LAST_RUN esteja em 2023-01-01 para limpar os 'Desconhecidos'
    raw_last_run = Variable.get("NVD_LAST_RUN", default_var="2023-01-01T00:00:00+00:00")
    current_start = datetime.fromisoformat(raw_last_run.strip()).astimezone(timezone.utc)
    final_end = datetime.now(timezone.utc)

    conn = pg_hook.get_conn()
    cur = conn.cursor()

    while current_start < final_end:
        current_end = min(current_start + timedelta(days=120), final_end)
        start_index = 0
        total_results = 1

        while start_index < total_results:
            params = {
                "resultsPerPage": 2000,
                "startIndex": start_index,
                "lastModStartDate": current_start.strftime("%Y-%m-%dT%H:%M:%SZ"),
                "lastModEndDate": current_end.strftime("%Y-%m-%dT%H:%M:%SZ"),
            }
            response = requests.get(base_url, headers=headers, params=params, timeout=60)
            if response.status_code != 200: break
            
            data = response.json()
            total_results = data.get("totalResults", 0)
            vulnerabilities = data.get("vulnerabilities", [])

            for item in vulnerabilities:
                cve = item.get("cve", {})
                json_str = json.dumps(item)
                
                # --- EXTRAÇÃO DE VENDOR POR REGEX (SÓ O QUE IMPORTA) ---
                vendor = "Desconhecido"
                # Esta é a lógica que você validou no SQL: pega o que vem depois de cpe:2.3:x:
                match = re.search(r'cpe:2\.3:[a-z]:([^:]+):', json_str)
                if match:
                    vendor = match.group(1).capitalize()
                elif cve.get("vulnStatus") == "Rejected":
                    vendor = "Rejected"

                # Extração segura das métricas para evitar o erro de NoneType
                metrics = cve.get("metrics", {})
                cvss = None
                for v in ["cvssMetricV40", "cvssMetricV31", "cvssMetricV30"]:
                    if metrics.get(v):
                        cvss = metrics[v][0].get("cvssData", {})
                        break

                cur.execute("""
                    INSERT INTO vulnerability.nvd_cves (
                        cve_id, vendor, base_score, severidade, 
                        complexidade_ataque, interacao_usuario, vetor_string_completo, json_original
                    ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                    ON CONFLICT (cve_id) DO UPDATE SET
                        vendor = EXCLUDED.vendor,
                        base_score = EXCLUDED.base_score,
                        severidade = EXCLUDED.severidade,
                        complexidade_ataque = EXCLUDED.complexidade_ataque,
                        interacao_usuario = EXCLUDED.interacao_usuario,
                        vetor_string_completo = EXCLUDED.vetor_string_completo;
                """, (
                    cve.get("id"), 
                    vendor, 
                    cvss.get("baseScore") if cvss else None,
                    cvss.get("baseSeverity") if cvss else None,
                    cvss.get("attackComplexity") if cvss else None,
                    cvss.get("userInteraction") if cvss else None,
                    cvss.get("vectorString") if cvss else None,
                    json_str
                ))
            conn.commit()
            start_index += 2000
            time.sleep(6) # Rate limit obrigatório

        current_start = current_end
        Variable.set("NVD_LAST_RUN", current_end.isoformat())
    cur.close(); conn.close()

with DAG(
    dag_id="dag_03_backfill_enriquecido", 
    start_date=datetime(2026, 1, 1), 
    schedule_interval=None, 
    catchup=False
) as dag:
    PythonOperator(task_id="carga_full_nvd", python_callable=fetch_nvd_incremental)
