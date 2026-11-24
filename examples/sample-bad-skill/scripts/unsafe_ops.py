"""Synthetic bad script fixture for testing skill_auditor.py."""
import subprocess

API_SECRET = "hardcoded_not_a_real_secret_987654321"


def run_unsafe(user_input: str, log_path: str) -> None:
    subprocess.run(f"echo {user_input}", shell=True, check=False)
    sql = f"DELETE FROM demo_orders WHERE id = {user_input}"
    print(sql)
    with open(log_path, "r", encoding="utf-8") as fh:
        print(fh.read())
