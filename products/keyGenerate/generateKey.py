import base64

from Crypto.Hash import SHA1, SHA256
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Util.asn1 import DerSequence, DerObjectId, DerNull, DerOctetString
from Crypto.Util.number import ceil_div
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding


# noinspection PyTypeChecker
def pkcs15_encode(msg_hash, emLen, with_hash_parameters=True):
    """
    Implement the ``EMSA-PKCS1-V1_5-ENCODE`` function, as defined
    :param msg_hash: hash object
    :param emLen: int
    :param with_hash_parameters: bool
    :return: An ``emLen`` byte long string that encodes the hash.
    """
    digestAlgo = DerSequence([DerObjectId(msg_hash.oid).encode()])

    if with_hash_parameters:
        digestAlgo.append(DerNull().encode())

    digest = DerOctetString(msg_hash.digest())
    digestInfo = DerSequence([
        digestAlgo.encode(),
        digest.encode()
    ]).encode()

    # We need at least 11 bytes for the remaining data: 3 fixed bytes and
    # at least 8 bytes of padding).
    if emLen < len(digestInfo) + 11:
        raise TypeError("Selected hash algorithm has a too long digest (%d bytes)." % len(digest))
    PS = b'\xFF' * (emLen - len(digestInfo) - 3)
    return b'\x00\x01' + PS + b'\x00' + digestInfo


# 从证书文件读取公钥
with open("ca.crt", "rb") as f:
    pem_data = f.read()

certBase64 = base64.b64encode(pem_data).decode()  # PEM 内容整体 Base64 编码
cert = x509.load_pem_x509_certificate(pem_data)

# certBase64 = "MIIExTCCAq2gAwIBAgIUE7nygTaURk+PZhBieKaWK/XJ5XgwDQYJKoZIhvcNAQELBQAwGDEWMBQGA1UEAwwNSmV0UHJvZmlsZSBDQTAeFw0yNTA3MDkwMTA0MTlaFw0zNTA3MDgwMTA0MTlaMCExHzAdBgNVBAMMFk1vWXVuby1mcm9tLTIwMjItMDctMjUwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQC4h4KfQwKFnGXfHNAW84t8CXGyvV/BX/PfKvNUIcTT0oPsS/0Rp+WnorT1oq/R0fVaElKH9744kSJDWz78ahYCghsvQD0S/ypgec38fdGUCVtj/nD3bmihqhOsTleU06OtoFnv7sCxLClQ66N/NNpPI0x8mvpSBG25f1HeczBmL1KTLvCb1cR624H+XgLBNDyY+kqPcDVnBY4FZuJ9isk3N8nzeQu9MYvK9+/nnwVCL392P6dUUagGfCjgAixxVL1rDa/7QcVpeeuYHXREzzek94PxGFgCZEk8JNIOY0yvLk7b7jzziAUE0kouOonyOVjEoQBeDZK/cDse1q5K6l0x7rCmYq67YNcJDu1jBilXKuMiv6DgxmPihLbBLVFYkow0bkjguZNMRMGtSu/8ioiT/wd4Bo6XiSv5X1OvSu6eYmmhkl3oQcu90h5mdUEaiJou6/BPixmdtA6u2j6lDHLek89xvuWAqpYsGeKZg6OS5qIcfvTfeEWgi1Z8V3QRmkFnMndMRFLOK/7BiF7Q9NUNsHsFpsJoFyKjxsWW/BvN0eBmB+w7s41kgfF7iGC6UGNNaZXuGdReDOXEevbgpxxKkZ+uVpTpYdS1987Q77vfAbtP4CUc1hnqb5wuocd5XPKS4/dKwrlAQT1o1yehe/rBtcnnZo2v9bzgmZus+/ZO8wIDAQABMA0GCSqGSIb3DQEBCwUAA4ICAQAnYagd8g5tXhVOHvbLI5TeLMTjpeWmylR7c61EPd8MnnY1Npqreqjun5fAjuiGgOAPZMNyxKN3SN1prjBtZE2VrjeSo9JdU8b/vUIjOsuCyEfXsaQFH33811Y6BWy6junAbIbwPILDIjg1edKZD/s516XbOL4nX6eIjD8FkuDz9svTyLTcwxrSnyE5XlGGuiKIPrKOKT7PV2nAnQBlSikeZPhqBrp0Pf5ViE/05YbhcFB3N+BDuhHDswaM0fNcsc00hLdP+5+ywsTxNg+gUZ2beh3Sbc1NC6WAfWi2WTgJ6uA4e1O/eKnIHg3Hq1DmWz4MlfeUyzD6gBVYG2XJ9PpV+Yx7MF05lYbblFTID+Sq4/QXsq3e4iS8RKoyFiogPzj+NKZ36gnkxtp8iS/PoPAkAA+aES9r8SzEbkORMvh/if/J/hsrGfW0cu1aGAYf2FZZ1qUCOkKvzSHX6bHQP4bZ/rEDZ9P467diWzCcOathUIXFFKyRTmU4jC10SP94+/nfM9qW2CaOoj697iYkaJ5BSMbsLwRBJjeCceXMg7PzaR93VHUnHkwaA17Ru3L31x+TNENaW1GY2Y2ekQx9cHIvTujekQKuztSffS9H/2dUpEuo96UR+eTPNi6zL4y11pQCw2p49Np7AUhpZyDA/jMUIIYqBxV5gK2TWL7dPxtQhQ=="
# cert = x509.load_der_x509_certificate(base64.b64decode(certBase64))

public_key = cert.public_key()
sign = int.from_bytes(cert.signature, byteorder="big", )
print(f"sign:{sign}")
print('\n')

modBits = public_key.key_size
digest_cert = SHA256.new(cert.tbs_certificate_bytes)
r = int.from_bytes(pkcs15_encode(digest_cert, ceil_div(modBits, 8)), byteorder='big', signed=False)
print(f"result:{r}")
print('\n')

licenseId = 'ZCB571FZHV'
licensePart = '{"licenseId": "ZCB571FZHV", "licenseeName": "MoYuno", "assigneeName": "", "assigneeEmail": "", "licenseRestriction": "", "checkConcurrentUse": false, "products": [{"code": "PDB", "fallbackDate": "2099-12-31", "paidUpTo": "2099-12-31", "extended": true}, {"code": "PSI", "fallbackDate": "2099-12-31", "paidUpTo": "2099-12-31", "extended": true}, {"code": "PPC", "fallbackDate": "2099-12-31", "paidUpTo": "2099-12-31", "extended": true}, {"code": "PCWMP", "fallbackDate": "2099-12-31", "paidUpTo": "2099-12-31", "extended": true}, {"code": "PPS", "fallbackDate": "2099-12-31", "paidUpTo": "2099-12-31", "extended": true}, {"code": "PRB", "fallbackDate": "2099-12-31", "paidUpTo": "2099-12-31", "extended": true}, {"code": "II", "fallbackDate": "2099-12-31", "paidUpTo": "2099-12-31", "extended": false}, {"code": "PGO", "fallbackDate": "2099-12-31", "paidUpTo": "2099-12-31", "extended": true}, {"code": "PSW", "fallbackDate": "2099-12-31", "paidUpTo": "2099-12-31", "extended": true}, {"code": "PWS", "fallbackDate": "2099-12-31", "paidUpTo": "2099-12-31", "extended": true}], "metadata": "0120220701PSAN000005", "hash": "TRIAL:-594988122", "gracePeriodDays": 7, "autoProlongated": false, "isAutoProlongated": false}'

digest = SHA1.new(licensePart.encode('utf-8'))

# 取私钥文件生成加密结果
with open('ca.key') as prifile:
    private_key = RSA.import_key(prifile.read())
    # 使用私钥对HASH值进行签名
    signature = pkcs1_15.new(private_key).sign(digest)

    sig_results = base64.b64encode(signature)
    licensePartBase64 = base64.b64encode(bytes(licensePart.encode('utf-8')))
    public_key.verify(
        base64.b64decode(sig_results),
        base64.b64decode(licensePartBase64),
        padding=padding.PKCS1v15(),
        algorithm=hashes.SHA1(),
    )
    result = licenseId + "-" + licensePartBase64.decode('utf-8') + "-" + sig_results.decode('utf-8') + "-" + certBase64
    print(result)
