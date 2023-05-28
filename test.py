import json
import base64
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
import os
# 公钥文件路径
public_key_path = 'public_key.pem'

# 用户名和密码
username = 'user123'
password = 'pass456'

# 组装用户名和密码为JSON对象
data = {
    'username': username,
    'password': password
}
json_data = json.dumps(data).encode('utf-8')

# 加载公钥
with open(public_key_path, 'rb') as key_file:
    public_key = serialization.load_pem_public_key(
        key_file.read(),
        backend=default_backend()
    )

# 使用公钥进行加密
encrypted_data = public_key.encrypt(
    json_data,
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
)

# Base64编码输出加密后的密文
encrypted_data_base64 = base64.b64encode(encrypted_data).decode('utf-8')
print("加密后的密文(Base64编码)：", encrypted_data_base64)
