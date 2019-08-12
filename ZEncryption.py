from Crypto.Hash import CMAC
from Crypto.Cipher import AES
from drbg import CTRDRBG
import binascii


#Extract a 16 byte key from the Curve25519 shared secret and both public keys (A is the including node, N is the joining node)
def CKDFTempExtract(secret, pub_a, pub_b):
    # Constant serves as CMAC key
    constant = b"\x33\x33\x33\x33\x33\x33\x33\x33\x33\x33\x33\x33\x33\x33\x33\x33"
    cobj = CMAC.new(constant, ciphermod=AES)
    cobj.update(secret+pub_a+pub_b)
    out = cobj.hexdigest()
    return out.decode("hex")

#Expand a 16 byte key to a 16 byte key and a personalisation string (Input should come from CKDFTempExtract)
def CKDFTempExpand(key):
    constant = b"\x88\x88\x88\x88\x88\x88\x88\x88\x88\x88\x88\x88\x88\x88\x88"
    cobj = CMAC.new(key, ciphermod=AES)
    cobj.update(constant + b"\x01")
    TempKeyCCM = cobj.hexdigest()
    cobj = CMAC.new(key, ciphermod=AES)
    cobj.update(TempKeyCCM.decode("hex") + constant + b"\x02")
    T2 = cobj.hexdigest()
    cobj = CMAC.new(key, ciphermod=AES)
    cobj.update(T2.decode("hex") + constant + b"\x03")
    T3 = cobj.hexdigest()
    temp_personalisation_string = T1+T2
    return (TempKeyCCM.decode("hex"), (temp_personalisation_string).decode("hex"))

#Expands the 16 byte permanent network key into a CCM key a personalisation string and an MPAN
def CKDFNetworkKeyExpand(key):
    constant = b"\x55\x55\x55\x55\x55\x55\x55\x55\x55\x55\x55\x55\x55\x55\x55"
    cobj = CMAC.new(key, ciphermod=AES)
    cobj.update(constant + b"\x01")
    KeyCCM = cobj.hexdigest()
    cobj = CMAC.new(key, ciphermod=AES)
    cobj.update(KeyCCM.decode("hex") + constant + b"\x02")
    T2 = cobj.hexdigest()
    cobj = CMAC.new(key, ciphermod=AES)
    cobj.update(T2.decode("hex") + constant + b"\x03")
    T3 = cobj.hexdigest()
    cobj = CMAC.new(key, ciphermod=AES)
    cobj.update(T3.decode("hex") + constant + b"\x04")
    T4 = cobj.hexdigest()
    personalisation_string = T2 + T3
    MPAN = T4

    return (KeyCCM.decode("hex"), (personalisation_string).decode("hex"))

#Mixes the entropy of sender and reciever
def CKDFMEIExtract(sEntropy, rEntropy):
    constant = b"\x26\x26\x26\x26\x26\x26\x26\x26\x26\x26\x26\x26\x26\x26\x26\x26"
    cobj = CMAC.new(constant, ciphermod=AES)
    cobj.update(sEntropy + rEntropy)
    NoncePRK = cobj.hexdigest()
    return NoncePRK.decode("hex")

#Expands a PRK into a MEI (PRK should come from the mixed entropy)
def CKDFMEIExpand(NoncePRK):
    constant = b"\x88\x88\x88\x88\x88\x88\x88\x88\x88\x88\x88\x88\x88\x88\x88"
    cobj = CMAC.new(NoncePRK , ciphermod=AES)
    cobj.update(constant + b"\x00" + constant + b"\x01")
    T1 = cobj.hexdigest()
    cobj = CMAC.new(NoncePRK , ciphermod=AES)
    cobj.update(T1.decode("hex") + constant + b"\x02")
    T2 = cobj.hexdigest()
    return (T1+T2).decode("hex")

#Instantiate a new ctr_drbg
def instantiateCTR(MEI, personalisation_string):
    drbg = CTRDRBG("aes128", MEI, personalisation_string)
    return drbg

#Generate a new nonce based on a ctr_drbg (truncated to 13 bytes)
def generateNonce(drbg):
    nonce = drbg._generate(16, "")
    return nonce[0:13]

#Encrypt a Z-wave message. Takes an encryption key, a nonce, an aad(for authentication) and the plaintext as input.
#Returns the Nonce, the Ciphertext and the MAC as output (MAC is set to 8 bytes)
def zEncrypt(key, nonce, aad, plaintext):
    cipher = AES.new(key, AES.MODE_CCM, nonce, mac_len=8)
    cipher.update(aad)
    msg = (nonce.encode('hex'), cipher.encrypt(plaintext).encode('hex'), cipher.digest().encode('hex'))
    return msg


#Decrypt an encrypted Z-wave message.Takes an encryption key, a nonce, an aad(not used because authentication is not preformed) and the ciphertext as input.
#Returns the plaintext
def zDecrypt(key, nonce, ciphertext, mac, aad):
    cipher = AES.new(key, AES.MODE_CCM, nonce)
    cipher.update(aad)
    plaintext = cipher.decrypt(ciphertext)
    return plaintext.encode("hex")
