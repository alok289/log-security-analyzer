import re
from collections import Counter

LOG_FILE = "security.log"
REPORT_FILE = "security_report.txt"


def load_logs():
    try:
        with open(LOG_FILE, "r") as file:
            return file.readlines()
    except FileNotFoundError:
        print("Log file not found.")
        return []


def analyze_logs(logs):
    failed_logins = []
    successful_logins = []
    ip_addresses = []

    for line in logs:
        ip_match = re.search(r"IP=(\d+\.\d+\.\d+\.\d+)", line)

        if ip_match:
            ip_addresses.append(ip_match.group(1))

        if "FAILED_LOGIN" in line:
            failed_logins.append(line.strip())

        elif "SUCCESS_LOGIN" in line:
            successful_logins.append(line.strip())

    return failed_logins, successful_logins, ip_addresses


def find_suspicious_ips(failed_logins):
    failed_ips = []

    for line in failed_logins:
        ip_match = re.search(r"IP=(\d+\.\d+\.\d+\.\d+)", line)

        if ip_match:
            failed_ips.append(ip_match.group(1))

    ip_count = Counter(failed_ips)

    suspicious_ips = {}

    for ip, count in ip_count.items():
        if count >= 3:
            suspicious_ips[ip] = count

    return suspicious_ips


def generate_report(failed_logins, successful_logins, suspicious_ips):
    report = []

    report.append("LOG ANALYSIS & SECURITY THREAT DETECTION REPORT")
    report.append("-----------------------------------------------")
    report.append("")
    report.append("Total failed login attempts: " + str(len(failed_logins)))
    report.append("Total successful logins: " + str(len(successful_logins)))
    report.append("")

    report.append("Suspicious IP Addresses")
    report.append("-----------------------")

    if suspicious_ips:
        for ip, count in suspicious_ips.items():
            report.append(ip + " - " + str(count) + " failed attempts")
    else:
        report.append("No suspicious IP addresses detected.")

    report.append("")
    report.append("Failed Login Attempts")
    report.append("---------------------")

    for login in failed_logins:
        report.append(login)

    with open(REPORT_FILE, "w") as file:
        file.write("\n".join(report))

    return report


def main():
    print("Log Analysis & Security Threat Detection System")
    print("-----------------------------------------------")

    logs = load_logs()

    if not logs:
        return

    failed_logins, successful_logins, ip_addresses = analyze_logs(logs)

    suspicious_ips = find_suspicious_ips(failed_logins)

    print("\nSecurity Analysis")
    print("-----------------")

    print("Failed login attempts:", len(failed_logins))
    print("Successful logins:", len(successful_logins))

    print("\nSuspicious IP Addresses:")

    if suspicious_ips:
        for ip, count in suspicious_ips.items():
            print(ip, "-", count, "failed attempts")
    else:
        print("No suspicious IP addresses detected.")

    generate_report(
        failed_logins,
        successful_logins,
        suspicious_ips
    )

    print("\nSecurity report saved as:", REPORT_FILE)


main()