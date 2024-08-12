import streamlit as st
import pandas as pd
import matplotlib.pyplot as plt
from pymongo import MongoClient
import bcrypt

# Conexão com o MongoDB
client = MongoClient("mongodb+srv://rodrigosobral:Sobral89@problemas.tv12d.mongodb.net/?retryWrites=true&w=majority&appName=problemas")
db = client["problemas"]
collection = db["problemas"]
collection_users = db["users"]

# Função para carregar problemas do MongoDB
def carregar_problemas():
    problemas = list(collection.find({}, {"_id": 0}))  # Retira o campo _id ao carregar os dados
    return problemas

# Função para salvar problemas no MongoDB
def salvar_problema(problema):
    collection.insert_one(problema)

# Função para carregar usuário
def carregar_usuario(username):
    user = collection_users.find_one({"username": username})
    return user

# Função para cadastrar usuário
def cadastrar_usuario(username, password, pergunta_seguranca, resposta_seguranca):
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
    hashed_resposta = bcrypt.hashpw(resposta_seguranca.encode('utf-8'), bcrypt.gensalt())
    collection_users.insert_one({
        "username": username, 
        "password": hashed_password, 
        "pergunta_seguranca": pergunta_seguranca,
        "resposta_seguranca": hashed_resposta
    })

# Função para verificar senha
def verificar_senha(password, hashed):
    return bcrypt.checkpw(password.encode('utf-8'), hashed)

# Função para cadastrar problemas
def cadastrar_problema():
    st.header("Cadastrar Problema")
    
    with st.form("Cadastro de Problema"):
        titulo = st.text_input("Título do Problema", max_chars=100)
        descricao = st.text_area("Descrição", max_chars=500)
        severidade = st.selectbox("Severidade", ["Baixa", "Média", "Alta", "Crítica"])
        status = st.selectbox("Status", ["Aberto", "Em andamento", "Resolvido", "Fechado"])
        submit_button = st.form_submit_button("Cadastrar")

        if submit_button:
            novo_problema = {"Título": titulo, "Descrição": descricao, "Severidade": severidade, "Status": status}
            salvar_problema(novo_problema)  # Salva o problema no MongoDB
            st.success("Problema cadastrado com sucesso!")

# Função para exibir dashboard
def exibir_dashboard():
    st.header("Dashboard de Problemas")
    
    problemas = carregar_problemas()

    # Verifica se existem problemas cadastrados
    if len(problemas) > 0:
        df = pd.DataFrame(problemas)
        
        st.subheader("Problemas por Severidade")
        fig, ax = plt.subplots()
        df["Severidade"].value_counts().plot(kind='bar', ax=ax, color="skyblue")
        ax.set_title("Distribuição dos Problemas por Severidade")
        ax.set_xlabel("Severidade")
        ax.set_ylabel("Quantidade")
        st.pyplot(fig)

        st.subheader("Problemas por Status")
        fig, ax = plt.subplots()
        df["Status"].value_counts().plot(kind='bar', ax=ax, color="lightgreen")
        ax.set_title("Distribuição dos Problemas por Status")
        ax.set_xlabel("Status")
        ax.set_ylabel("Quantidade")
        st.pyplot(fig)
    else:
        st.warning("Nenhum problema cadastrado ainda!")

# Função para criar a página de login
def login():
    if not st.session_state["logged_in"]:
        st.header("Login")

        username = st.text_input("Usuário")
        password = st.text_input("Senha", type="password")

        if st.button("Login"):
            user = carregar_usuario(username)
            if user and verificar_senha(password, user["password"]):
                st.session_state["logged_in"] = True
                st.session_state["username"] = username
                st.success("Login bem-sucedido!")
                main()
                st.rerun()

            else:
                st.error("Usuário ou senha incorretos")

# Função para criar a página de registro
def registro():
    st.header("Registrar-se")

    username = st.text_input("Novo Usuário")
    password = st.text_input("Nova Senha", type="password")
    password_confirm = st.text_input("Confirmar Senha", type="password")
    pergunta_seguranca = st.text_input("Pergunta de Segurança")
    resposta_seguranca = st.text_input("Resposta de Segurança")

    if st.button("Registrar"):
        if password != password_confirm:
            st.error("As senhas não coincidem")
        else:
            if carregar_usuario(username):
                st.error("Usuário já existe")
            else:
                cadastrar_usuario(username, password, pergunta_seguranca, resposta_seguranca)
                st.success("Usuário registrado com sucesso!")

# Função para redefinir a senha
def redefinir_senha():
    st.header("Redefinir Senha")

    username = st.text_input("Usuário")
    pergunta_seguranca = st.text_input("Pergunta de Segurança")

    if st.button("Enviar"):
        user = carregar_usuario(username)
        if user and user["pergunta_seguranca"] == pergunta_seguranca:
            resposta_seguranca = st.text_input("Resposta de Segurança")
            if st.button("Verificar"):
                if verificar_senha(resposta_seguranca, user["resposta_seguranca"]):
                    nova_senha = st.text_input("Nova Senha", type="password")
                    nova_senha_confirm = st.text_input("Confirmar Nova Senha", type="password")
                    if nova_senha == nova_senha_confirm:
                        hashed_nova_senha = bcrypt.hashpw(nova_senha.encode('utf-8'), bcrypt.gensalt())
                        collection_users.update_one({"username": username}, {"$set": {"password": hashed_nova_senha}})
                        st.success("Senha redefinida com sucesso!")
                    else:
                        st.error("As senhas não coincidem")
                else:
                    st.error("Resposta de segurança incorreta")
        else:
            st.error("Usuário ou pergunta de segurança incorretos")

# Função principal para exibir as páginas após login
def main():
    st.sidebar.title("Navegação")
    pagina_selecionada = st.sidebar.selectbox("Escolha uma página", ["Cadastrar Problema", "Dashboard", "Esqueci Minha Senha"])

    if pagina_selecionada == "Cadastrar Problema":
        cadastrar_problema()
    elif pagina_selecionada == "Dashboard":
        exibir_dashboard()
    elif pagina_selecionada == "Esqueci Minha Senha":
        redefinir_senha()

# Página principal que verifica se o usuário está logado
if "logged_in" not in st.session_state:
    st.session_state["logged_in"] = False

if st.session_state["logged_in"]:
    main()
else:
    escolha = st.sidebar.selectbox("Escolha", ["Login", "Registrar-se", "Esqueci Minha Senha"])
    if escolha == "Login":
        login()
    elif escolha == "Registrar-se":
        registro()
    elif escolha == "Esqueci Minha Senha":
        redefinir_senha()
