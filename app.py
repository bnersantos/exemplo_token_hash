from flask import Flask, jsonify,request
from sqlalchemy import select
from models import UsuarioExemplo, NotasExemplo, SessionLocalExemplo
from functools import wraps
from flask_jwt_extended import create_access_token, JWTManager, get_jwt_identity, jwt_required

app = Flask(__name__)
app.config['JWT_SECRET_KEY'] = 'b1bl107&ca_461'
jwt = JWTManager(app)
db_session = SessionLocalExemplo

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        current_user = get_jwt_identity()
        db_session = SessionLocalExemplo()
        try:
            sql = select(UsuarioExemplo).where(UsuarioExemplo.id == current_user)
            user = db_session.execute(sql).scalar()
            if user and user.papel == 'admin':
                return f(*args, **kwargs)
            return jsonify({
                "msg": "Acesso negado, privilégio de adminstrador necessário."
            }), 401
        finally:
            db_session.close()
    return decorated_function

@app.route('/login', methods=['POST'])
def login():
    dados = request.get_json()
    email = dados.get('email')
    senha = dados.get('senha')

    db_session = SessionLocalExemplo()

    try:
        sql = select(UsuarioExemplo).where(UsuarioExemplo.email == email)
        user = db_session.execute(sql).scalar()

        if user and user.check_password(senha):
            access_token = create_access_token(identity=email)
            return jsonify({
                access_token: access_token
            })
        else:
            return jsonify({
                "msg": "Credenciais inválidas."
            }), 401
    except Exception as e:
        print(e)
    finally:
        db_session.close()

@app.route('/cadastro', methods=['POST'])
@jwt_required
@admin_required
def cadastro():
    dados = request.get_json()
    nome = dados['nome']
    email = dados['email']
    senha = dados['senha']
    papel = dados.get['papel']


    if not nome or not email or not senha:
        return jsonify({"msg": "Nome de usuário e senha são obrigatórios"}), 400

    try:
        # Verificar se o usuário já existe
        user_check = select(UsuarioExemplo).where(UsuarioExemplo.email == email)
        usuario_existente = db_session.execute(user_check).scalar()

        if usuario_existente:
            return jsonify({"msg": "Usuário já existe"}), 400

        novo_usuario = UsuarioExemplo(nome=nome, email=email, papel=papel)
        novo_usuario.set_senha_hash(senha)
        db_session.add(novo_usuario)
        db_session.commit()

        user_id = novo_usuario.id
        return jsonify({"msg": "Usuário criado com sucesso", "user_id": user_id}), 201
    except Exception as e:
        db_session.rollback()
        return jsonify({"msg": f"Erro ao registrar usuário: {str(e)}"}), 500
    finally:
        db_session.close()

@app.route('/listar_usuarios', methods=['GET'])
@jwt_required
@admin_required
def listar_usuarios():
    db_session = SessionLocalExemplo()
    sql = select(UsuarioExemplo).order_by(UsuarioExemplo.nome)
    usuarios = db_session.execute(sql).scalars() # scalars como obj e all em dic
    try:
        lista_usuarios = []
        for usuario in usuarios:
            lista_usuarios.append(usuario.serialize())
        return jsonify({
            lista_usuarios
        })
    except Exception as e:
        return  jsonify({
            "msg": "Erro ao listar os dados."
        })
    finally:
        db_session.close()
@app.route('/notas_exemplo', methods=['POST'])
@jwt_required
def criar_nota_exemplo():
    data = request.get_json()
    conteudo = data.get('conteudo')

    if not conteudo:
        return jsonify({"msg": "Conteúdo da nota é obrigatório"}), 400

    db = SessionLocalExemplo()
    try:
        nova_nota = NotasExemplo(conteudo=conteudo)
        # Se quisesse associar ao usuário: nova_nota.user_id = current_user_id
        db.add(nova_nota)
        db.commit()
        nota_id = nova_nota.id
        return jsonify({"msg": "Nota criada", "nota_id": nota_id}), 201
    except Exception as e:
        db.rollback()
        return jsonify({"msg": f"Erro ao criar nota: {str(e)}"}), 500
    finally:
        db.close()

@app.route('/notas_exemplo', methods=['GET'])
@jwt_required
@admin_required
def listar_notas_exemplo():
    db = SessionLocalExemplo()
    try:
        stmt = select(NotasExemplo)
        notas_result = db.execute(stmt).scalars().all() # .scalars().all() para obter uma lista de objetos
        notas_list = [{"id": nota.id, "conteudo": nota.conteudo} for nota in notas_result]
        return jsonify(notas_list)
    finally:
        db.close()

if __name__ == '__main__':
    app.run(debug=True, port=5001) # Rodar em uma porta diferente da API principal
