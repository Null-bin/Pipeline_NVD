import pandas as pd
from datetime import datetime
from airflow import DAG
from airflow.operators.python import PythonOperator
from airflow.providers.postgres.hooks.postgres import PostgresHook

def sync_cmdb_assets():
    # Conexão com o banco usando o dono da base (licitacoes_user)
    pg_hook = PostgresHook(postgres_conn_id='postgres_vulnerability')
    
    # Caminho do arquivo mapeado no seu volume Docker
    csv_path = '/opt/airflow/data/ativos_export.csv'
    
    print(f"Iniciando leitura do CMDB: {csv_path}")
    
    # Lendo o CSV com o encoding Windows-1252 identificado nas fotos
    df = pd.read_csv(csv_path, sep=',', encoding='cp1252')

    conn = pg_hook.get_conn()
    cur = conn.cursor()

    for _, row in df.iterrows():
        cur.execute("""
            INSERT INTO vulnerability.assets (
                desabilitado, fonte, asset_id, nome, tipo, sigla, 
                servico_vinculado, descricao, local, area, nome_dos_responsaveis,
                endereco_ip, usuarios, sistema_operacional_desatualizado, legado,
                identificacao_ambiente, backup, monitoracao_zabbix, monitoracao_dynatrace,
                data_hora_entrada, rvs_ativa, rvs_anotacao, nivel_impacto_negocio,
                ciclo_vida_servico, sensibilidade_dados, local_hospedagem_ambiente,
                seguranca_informacao, localizacao_ativo, media_criticidade,
                faixa_criticidade, identificador, hora_atualizacao
            ) VALUES (
                %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s,
                %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s
            ) ON CONFLICT (asset_id) DO UPDATE SET
                nome = EXCLUDED.nome,
                hora_atualizacao = CURRENT_TIMESTAMP,
                faixa_criticidade = EXCLUDED.faixa_criticidade,
                endereco_ip = EXCLUDED.endereco_ip;
        """, (
            row['Desabilitado'], row['Fonte'], row['Asset id'], row['Nome'], row['Tipo'], row['Sigla'],
            row['Serviço Vinculado'], row['Descrição'], row['Local'], row['Área'], row['Nome dos Responsáveis'],
            row['Endereço IP'], row['Usuários'], row['Sistema Operacional Desatualizado'], row['Legado'],
            row['Identificação Ambiente'], row['Backup'], row['Monitoração Zabbix'], row['Monitoração Dynatrace'],
            row['Data/Hora Entrada'], row['RVS Ativa'], row['RVS Anotação'], row['Nível de Impacto para o Negócio'],
            row['Ciclo de Vida do Serviço'], row['Sensibilidade dos Dados'], row['Local de Hospedagem do Ambiente'],
            row['Segurança da Informação'], row['Localização Ativo'], row['Média Criticidade'],
            row['Faixa de Criticidade'], row['Identificador'], datetime.now()
        ))
    
    conn.commit()
    cur.close()
    conn.close()
    print("Sincronização do CMDB finalizada com sucesso.")

with DAG(
    'dag_02_asset_sync',
    start_date=datetime(2026, 1, 1),
    schedule_interval='@daily',
    catchup=False,
    tags=['cmdb', 'vulnerability']
) as dag:

    sync_task = PythonOperator(
        task_id='sync_ativos_cmdb',
        python_callable=sync_cmdb_assets
    )
