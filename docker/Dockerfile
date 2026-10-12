FROM apache/airflow:2.9.3-python3.11

# dbt goes in its OWN virtualenv: installing it next to Airflow often causes
# dependency conflicts. The DAG calls /home/airflow/dbt_venv/bin/dbt directly.
RUN python -m venv /home/airflow/dbt_venv \
 && /home/airflow/dbt_venv/bin/pip install --no-cache-dir dbt-bigquery==1.8.2

# libraries our own ingestion code imports inside Airflow (airflow itself is pinned
# so pip cannot upgrade it)
RUN pip install --no-cache-dir "apache-airflow==2.9.3" google-cloud-bigquery requests python-dotenv
