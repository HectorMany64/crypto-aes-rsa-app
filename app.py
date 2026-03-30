from flask import Flask, render_template_string, request
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding as sym_padding
import os
import base64

app = Flask(__name__)

def generar_claves_rsa():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return private_key, private_key.public_key()

def cifrar_aes(mensaje, clave):
    iv = os.urandom(16)
    padder = sym_padding.PKCS7(128).padder()
    padded = padder.update(mensaje.encode()) + padder.finalize()
    cipher = Cipher(algorithms.AES(clave), modes.CBC(iv))
    encryptor = cipher.encryptor()
    cifrado = encryptor.update(padded) + encryptor.finalize()
    return iv, cifrado

def descifrar_aes(iv, cifrado, clave):
    cipher = Cipher(algorithms.AES(clave), modes.CBC(iv))
    decryptor = cipher.decryptor()
    decrypted = decryptor.update(cifrado) + decryptor.finalize()
    unpadder = sym_padding.PKCS7(128).unpadder()
    return (unpadder.update(decrypted) + unpadder.finalize()).decode()

def cifrar_clave_rsa(clave, public_key):
    return public_key.encrypt(
        clave,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

def descifrar_clave_rsa(clave_cifrada, private_key):
    return private_key.decrypt(
        clave_cifrada,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

HTML = """
<!DOCTYPE html>
<html>
<head>
<title>AES + RSA Azure</title>
<style>
body { font-family: Arial; background:#0f172a; color:white; padding:40px; }
textarea { width:100%; padding:10px; }
button { padding:10px; margin-top:10px; }
.box { background:#1e293b; padding:20px; border-radius:10px; }
</style>
</head>
<body>
<h1>🔐 Cifrado Híbrido (Azure Ready)</h1>
<div class="box">
<form method="POST">
<textarea name="mensaje" placeholder="Escribe tu mensaje..." required></textarea>
<button type="submit">Procesar</button>
</form>
</div>
{% if r %}
<div class="box">
<p><b>Cifrado AES:</b><br>{{r.c}}</p>
<p><b>Clave cifrada RSA:</b><br>{{r.k}}</p>
<p><b>Mensaje recuperado:</b><br>{{r.d}}</p>
</div>
{% endif %}
</body>
</html>
"""

@app.route('/', methods=['GET','POST'])
def home():
    r=None
    if request.method=='POST':
        m=request.form['mensaje']
        clave=os.urandom(32)
        priv,pub=generar_claves_rsa()
        iv,cif=cifrar_aes(m,clave)
        clave_cif=cifrar_clave_rsa(clave,pub)
        clave_dec=descifrar_clave_rsa(clave_cif,priv)
        m2=descifrar_aes(iv,cif,clave_dec)
        r={
            "c": base64.b64encode(iv+cif).decode(),
            "k": base64.b64encode(clave_cif).decode(),
            "d": m2
        }
    return render_template_string(HTML,r=r)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 8000)))
