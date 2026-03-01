import boto3
import csv
from datetime import datetime, timedelta, timezone

# IAM client initialize
iam = boto3.client('iam')

def audit_users():
    report_data = []
    today = datetime.now(timezone.utc)
    ninety_days_ago = today - timedelta(days=90)

    # 1. Get All Users
    users = iam.list_users()['Users']

    for user in users:
        username = user['UserName']
        
        # 2. Get User Details
        password_last_used = "N/A"
        try:
            user_details = iam.get_user(UserName=username)
            if 'PasswordLastUsed' in user_details['User']:
                password_last_used = user_details['User']['PasswordLastUsed']
        except:
            pass

        # 3. Check MFA
        mfa_devices = iam.list_mfa_devices(UserName=username)['MFADevices']
        mfa_active = len(mfa_devices) > 0

        # 4. Check Access Keys
        access_keys = iam.list_access_keys(UserName=username)['AccessKeyMetadata']
        key_status = "No Keys"
        key_last_used = "N/A"
        if access_keys:
            key_status = "Active" if access_keys[0]['Status'] == 'Active' else "Inactive"
            # Get key last used info if available
            key_id = access_keys[0]['AccessKeyId']
            try:
                key_last_used_info = iam.get_access_key_last_used(AccessKeyId=key_id)
                if 'LastUsedDate' in key_last_used_info['AccessKeyLastUsed']:
                    key_last_used = key_last_used_info['AccessKeyLastUsed']['LastUsedDate']
            except:
                pass

        # 5. Check Policies (Permissions)
        policies = iam.list_user_policies(UserName=username)['PolicyNames']
        attached_policies = iam.list_attached_user_policies(UserName=username)['AttachedPolicies']
        permissions = " | ".join(policies) + " | " + " | ".join([p['PolicyName'] for p in attached_policies])

        # 6. RISK LOGIC (Context Based)
        risk_level = "LOW"
        action_required = "None"

        # Check for 90 days inactivity
        is_inactive = False
        if password_last_used != "N/A" and password_last_used < ninety_days_ago:
            is_inactive = True
        
        if is_inactive:
            risk_level = "CRITICAL"
            action_required = "DELETE USER (Inactive > 90 Days)"
        elif not mfa_active and password_last_used != "N/A":
            risk_level = "HIGH"
            action_required = "Enable MFA"
        elif key_status == "Active" and key_last_used != "N/A" and key_last_used < ninety_days_ago:
            risk_level = "HIGH"
            action_required = "Rotate/Disable Keys"

        report_data.append({
            'User': username,
            'MFA_Active': mfa_active,
            'Password_Last_Used': password_last_used,
            'Key_Status': key_status,
            'Key_Last_Used': key_last_used,
            'Permissions': permissions,
            'Risk_Level': risk_level,
            'Action_Required': action_required
        })

    # 7. Save to CSV
    with open('reports/all_in_one_audit.csv', 'w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=['User', 'MFA_Active', 'Password_Last_Used', 'Key_Status', 'Key_Last_Used', 'Permissions', 'Risk_Level', 'Action_Required'])
        writer.writeheader() # Corrected this line
        writer.writerows(report_data)
    
    print("Report generated: reports/all_in_one_audit.csv")

if __name__ == "__main__":
    audit_users()
