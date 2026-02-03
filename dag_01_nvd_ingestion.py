import requests
import time
import json
from datetime import datetime, timedelta, timezone

from airflow import DAG
from airflow.operators.python import PythonOperator
from airflow.models import Variable


def fetch_nvd_full_load():
    from airflow.providers.postgres.hooks.postgres import PostgresHook

    pg_hook = PostgresHook(postgres_conn_id="postgres_vulnerability")
    api_key = Variable.get("NVD_API_KEY")

    # ENDPOINT CORRETO NVD API v2
    base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"

    headers = {
        "Accept": "application/json",
        "User-Agent": "airflow-nvd-ingestion/1.0 (contact: guilherme.matos@infra-work.com)",
        "apiKey": api_key,
    }

    end_date = datetime.now(timezone.utc)
    start_date = end_date - timedelta(days=120)

    start_index = 0
    results_per_page = 2000
    total_results = 1

    conn = pg_hook.get_conn()
    cur = conn.cursor()

    print("Iniciando ingestão NVD")

    while start_index < total_results:
        params = {
            "resultsPerPage": results_per_page,
            "startIndex": start_index,
            "lastModStartDate": start_date.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "lastModEndDate": end_date.strftime("%Y-%m-%dT%H:%M:%SZ"),
        }

        response = requests.get(
            base_url,
            headers=headers,
            params=params,
            timeout=60,
        )

        if response.status_code != 200:
            raise Exception(
                f"NVD API error {response.status_code} - {response.text[:300]}"
            )

        data = response.json()
        total_results = data.get("totalResults", 0)
        vulnerabilities = data.get("vulnerabilities", [])

        if not vulnerabilities:
            print("Nenhum CVE retornado.")
            break

        for item in vulnerabilities:
            cve = item.get("cve", {})

            cur.execute(
                """
                INSERT INTO vulnerability.nvd_cves (
                    cve_id,
                    descricao,
                    data_ultima_modificacao,
                    json_original
                )
                VALUES (%s, %s, %s, %s)
                ON CONFLICT (cve_id) DO UPDATE SET
                    data_ultima_modificacao = EXCLUDED.data_ultima_modificacao,
                    json_original = EXCLUDED.json_original;
                """,
                (
                    cve.get("id"),
                    cve.get("descriptions", [{}])[0].get("value"),
                    cve.get("lastModified"),
                    json.dumps(item),
                ),
            )

        conn.commit()

        start_index += results_per_page
        print(f"Progresso: {start_index}/{total_results}")

        # Rate limit seguro com API key
        time.sleep(6)

    cur.close()
    conn.close()
    print("Carga NVD finalizada com sucesso")


with DAG(
    dag_id="dag_01_nvd_ingestion",
    start_date=datetime(2026, 1, 1),
    schedule_interval=None,
    catchup=False,
    tags=["nvd", "cve", "security"],
) as dag:

    carga_total_nvd = PythonOperator(
        task_id="carga_total_nvd",
        python_callable=fetch_nvd_full_load,
    )
