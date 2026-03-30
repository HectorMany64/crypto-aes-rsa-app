# ============================================
# VERSION FINAL WEB (BONITA + ESTABLE AZURE)
# ============================================
# ✔ Interfaz moderna
# ✔ AES + RSA funcional
# ✔ Compatible con Azure
# ============================================

from flask import Flask, render_template_string, request
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding as sym_padding
import os, base64

app = Flask(__name__)

# ================= AES =================
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

# ================= RSA =================
def generar_claves():
    priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return priv, priv.public_key()


def cifrar_rsa(clave, pub):
    return pub.encrypt(
        clave,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )


def descifrar_rsa(clave_cifrada, priv):
    return priv.decrypt(
        clave_cifrada,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

# ================= HTML MODERNO =================
HTML = """
<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<title>Cifrado AES + RSA</title>
<style>
body {
    font-family: 'Segoe UI';
    background: linear-gradient(135deg,#0f172a,#1e293b);
    color:white;
    display:flex;
    justify-content:center;
    align-items:center;
    height:100vh;
}
.container {
    background:#1e293b;
    padding:30px;
    border-radius:15px;
    width:500px;
    box-shadow:0 0 20px rgba(0,0,0,0.5);
}
textarea {
    width:100%;
    padding:10px;
    border-radius:8px;
    border:none;
}
button {
    margin-top:15px;
    width:100%;
    padding:12px;
    border:none;
    border-radius:8px;
    background:#38bdf8;
    color:black;
    font-weight:bold;
    cursor:pointer;
}
.result {
    margin-top:20px;
    background:#0f172a;
    padding:15px;
    border-radius:10px;
    word-wrap:break-word;
}
</style>
</head>
<body>
<div class="container">
<h2>🔐 Cifrado Híbrido AES + RSA</h2>
<form method="POST">
<textarea name="mensaje" placeholder="Escribe tu mensaje..." required></textarea>
<button type="submit">Cifrar y Descifrar</button>
</form>

{% if r %}
<div class="result">
<p><b>Mensaje cifrado:</b><br>{{r.c}}</p>
<p><b>Clave cifrada:</b><br>{{r.k}}</p>
<p><b>Mensaje descifrado:</b><br>{{r.d}}</p>
</div>
{% endif %}
</div>
</body>
</html>
"""

# ================= RUTA =================
@app.route('/', methods=['GET','POST'])
def home():
    r=None
    if request.method=='POST':
        m=request.form['mensaje']
        clave=os.urandom(32)
        priv,pub=generar_claves()

        iv,cif=cifrar_aes(m,clave)
        clave_cif=cifrar_rsa(clave,pub)
        clave_dec=descifrar_rsa(clave_cif,priv)
        m2=descifrar_aes(iv,cif,clave_dec)

        r={
            "c": base64.b64encode(iv+cif).decode(),
            "k": base64.b64encode(clave_cif).decode(),
            "d": m2
        }

    return render_template_string(HTML,r=r)

# ================= ARRANQUE =================
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 8000)))

# ============================================
# requirements.txt
# ============================================
# flask
# cryptography
# gunicorn

# ============================================
# STARTUP AZURE
# ============================================
# gunicorn --bind=0.0.0.0 --timeout 600 app:app

