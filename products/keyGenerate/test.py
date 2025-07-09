# 读取 ca.crt 文件内容并清理
with open('ca.crt', 'r') as file:
    cert_str = file.read()

# 去除首尾的 PEM 证书头和尾，并去掉所有换行符
cert_clean = cert_str.strip("-----BEGIN CERTIFICATE-----\n-----END CERTIFICATE-----\n").replace('\n', '')

# 输出清理后的字符串
print(cert_clean)