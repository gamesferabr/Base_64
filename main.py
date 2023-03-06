import base64
import os
from io import BytesIO
from flask import Flask, render_template, request, redirect, url_for, send_file
from flask_login import LoginManager, UserMixin, login_user, login_required
from flask_bcrypt import Bcrypt

app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(24)

bcrypt = Bcrypt(app)


# Cria um objeto LoginManager para gerenciar a autenticação do usuário
login_manager = LoginManager()
login_manager.init_app(app)


# Define uma classe User que representa um usuário no sistema
class User(UserMixin):
    def __init__(self, username, password_hash):
        self.username = username
        self.password_hash = password_hash

    def get_id(self):
        return self.username


# Define uma lista de usuários válidos
users = [
    User('myusernamesergio', bcrypt.generate_password_hash('mypasswordsergio').decode('utf-8'))
]


# Função que verifica se uma senha está correta
def verify_password(user, password):
    return bcrypt.check_password_hash(user.password_hash, password)


# Função que retorna um usuário com um determinado nome de usuário
def get_user(username):
    for user in users:
        if user.username == username:
            return user


# Função que é executada para carregar um usuário a partir de um cookie de sessão
@login_manager.user_loader
def load_user(username):
    return get_user(username)


@app.route('/', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = get_user(username)
        if user is not None and verify_password(user, password):
            login_user(user)
            return redirect(url_for('pdf'))

        else:
            error = 'Usuário ou senha inválidos.'
            return render_template('login.html', error=error)
    else:
        return render_template('login.html')


@app.route(f'/pdf', methods=['GET', 'POST'], )
@login_required
def pdf():
    if request.method == 'POST':
        arquivo = request.files['arquivo']
        # Codificar o arquivo em base64 e converter para PDF
        nome_arquivo,extensao = os.path.splitext(arquivo.filename)
        encoded_string = base64.b64decode(arquivo.read())
        return send_file(BytesIO(encoded_string), attachment_filename=f"{nome_arquivo}.pdf", as_attachment=False)
    
    return render_template('pdf.html')


if __name__ == '__main__':
    app.run(debug=True)