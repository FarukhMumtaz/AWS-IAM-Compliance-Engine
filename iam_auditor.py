import boto3
import csv
import logging
import time
from datetime import datetime, timezone

# Professional Logging
logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')
logger = logging.getLogger("EnterpriseAuditor")

class EnterpriseIAMEngine:
    def __init__(self):
        self.iam = boto3.client('iam')
        self.report_path = "reports/enterprise_security_audit.csv"

    def generate_credential_report(self):
        """AWS se deep security data (MFA, Password Age, etc.) ki report mangwana"""
        logger.info("📊 Generating AWS Credential Report...")
        while True:
            resp = self.iam.generate_credential_report()
            if resp['State'] == 'COMPLETE':
                break
            time.sleep(2)
        return self.iam.get_credential_report()['Content'].decode('utf-8')

    def run_audit(self):
        logger.info("🚀 Starting High-Level Security Intelligence Scan...")
        csv_data = self.generate_credential_report()
        reader = csv.DictReader(csv_data.splitlines())

        with open(self.report_path, 'w', newline='') as f:
            # High-Level Columns
            headers = [
                'User', 'MFA_Active', 'Password_Last_Changed', 
                'Password_Next_Rotation', 'Access_Key_1_Last_Used', 
                'Risk_Level', 'Compliance_Score'
            ]
            writer = csv.DictWriter(f, fieldnames=headers)
            writer.writeheader()

            for row in reader:
                if row['user'] == '<root_account>': continue

                # Deep Analysis Logic
                mfa = "SECURE" if row['mfa_active'] == 'true' else "CRITICAL_RISK"
                
                # Risk Calculation
                risk = "LOW"
                score = 100
                if row['mfa_active'] == 'false':
                    risk = "HIGH"
                    score -= 50
                if row['password_enabled'] == 'true' and row['password_last_changed'] == 'not_supported':
                    risk = "CRITICAL"
                    score -= 30

                writer.writerow({
                    'User': row['user'],
                    'MFA_Active': mfa,
                    'Password_Last_Changed': row['password_last_changed'],
                    'Password_Next_Rotation': row['password_next_rotation'],
                    'Access_Key_1_Last_Used': row['access_key_1_last_used_date'],
                    'Risk_Level': risk,
                    'Compliance_Score': f"{score}%"
                })

        logger.info(f"✅ Enterprise Audit Complete. Report: {self.report_path}")

if __name__ == "__main__":
    engine = EnterpriseIAMEngine()
    engine.run_audit()
