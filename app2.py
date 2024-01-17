import streamlit as st
from sqlalchemy import create_engine, text
import hashlib
import re

# Fonctions pour le hachage et la vérification des mots de passe
def make_hashes(password):
    return hashlib.sha256(str.encode(password)).hexdigest()

def check_hashes(password, hashed_text):
    return make_hashes(password) == hashed_text

def check_password_complexity(password):
    return len(password) >= 8 and any(char.isupper() for char in password) and any(char.isdigit() for char in password)

def check_email_validity(email):
    return re.match(r"[^@]+@[^@]+\.[^@]+", email) is not None

# Initialisation de la session state
if 'logged_in' not in st.session_state:
    st.session_state['logged_in'] = False

if 'show_register' not in st.session_state:
    st.session_state['show_register'] = False

if 'message' not in st.session_state:
    st.session_state['message'] = ""

# Connexion à la base de données
engine = create_engine("sqlite:///users.db")

# Création de la table des utilisateurs
with engine.connect() as conn:
    conn.execute(text('''
        CREATE TABLE IF NOT EXISTS users (
            username TEXT PRIMARY KEY, 
            email TEXT, 
            firstname TEXT, 
            lastname TEXT, 
            password TEXT
        );
    '''))

# Afficher un message (si présent) et le réinitialiser
if st.session_state['message']:
    st.success(st.session_state['message'])
    st.session_state['message'] = ""

# Contenu principal de l'application
if not st.session_state['logged_in']:
    st.subheader("Bienvenue dans l'application!")

    # Vue d'inscription
    with st.container():
        st.subheader("Créer un nouveau compte")

        # Vue d'inscription
        if st.session_state['show_register']:
            new_username = st.text_input("Nom d'utilisateur", key="new_username")
            new_email = st.text_input("Email", key="new_email")
            new_firstname = st.text_input("Prénom", key="new_firstname")
            new_lastname = st.text_input("Nom", key="new_lastname")
            new_password = st.text_input("Mot de passe", type='password', key="new_password")
            new_password2 = st.text_input("Confirmation du mot de passe", type='password')

            mdp_correspondant = new_password == new_password2
            complexite_mdp = check_password_complexity(new_password)
            email_valide = check_email_validity(new_email)

            if not mdp_correspondant:
                st.warning("Les mots de passe ne correspondent pas.")
            elif not complexite_mdp:
                st.warning("Le mot de passe ne respecte pas les critères de complexité.")
                st.warning("Le mot de passe doit contenir au moins 8 caractères, une majuscule et un chiffre.")
            elif not email_valide:
                st.warning("L'adresse e-mail n'est pas valide. Veuillez fournir une adresse e-mail correcte.")

            if st.button("S'inscrire", key="register"):
                hashed_new_password = make_hashes(new_password)
                with engine.connect() as conn:
                    conn.execute(text('''
                        INSERT INTO users (username, email, firstname, lastname, password) 
                        VALUES (:username, :email, :firstname, :lastname, :password);
                    '''), username=new_username, email=new_email, firstname=new_firstname, lastname=new_lastname, password=hashed_new_password)
                st.session_state['message'] = "Compte créé avec succès !"
                st.session_state['show_register'] = False
                st.experimental_rerun()
    # Vue de connexion
        else:
            username = st.text_input("Nom d'utilisateur", key="username")
            password = st.text_input("Mot de passe", type='password', key="password")
            
            if st.button("Se connecter", key="login"):
                with engine.connect() as conn:
                    result = conn.execute(text("SELECT * FROM users WHERE username=:username"), {'username': username})
                    user = result.fetchone()
                    
                    if user and check_hashes(password, user['password']):
                        st.session_state['logged_in'] = True
                        st.session_state['show_register'] = False
                        st.session_state['current_user'] = username
                        st.experimental_rerun()
                    else:
                        st.error("Identifiant ou mot de passe incorrect")

            if st.button("Créer un compte", key="go_to_register"):
                st.session_state['show_register'] = True
                st.experimental_rerun()

# Contenu principal de l'application après connexion
elif st.session_state['logged_in']:
    st.subheader("Bienvenue dans l'application!")

    current_user = st.session_state.get('current_user', None)
    st.subheader("Configuration des utilisateurs")
    conn = st.connection("users_db", "sql")
    user_list = conn.query("select  username, email from users;")

    st.dataframe(user_list)
    st.text("Supprimer le compte")
    st.subheader("Supprimer mon compte")

    user_name =st.text_input(label ='user name',key="user_name")

    password_confirm = st.text_input("Confirmer avec votre mot de passe", type='password', key="password_confirm")
    
    if st.button("Supprimer un compte", key="delete_account"):
        print(current_user)
        if current_user:
            with engine.connect() as conn:
                result = conn.execute(text("SELECT * FROM users WHERE username=:username"), {'username': current_user})
                user = result.fetchone()
                if user and check_hashes(password_confirm, user['password']):
                    conn.execute(text("DELETE FROM users WHERE username=:username"), {'username': user_name})
                    st.success("Compte supprimé avec succès!")
                    print("OOOOOOOOOOOOOOOOOOOOOOOOOKK")
                    st.session_state['logged_in'] = False
                    st.experimental_rerun()
                else:
                    st.warning("Mot de passe incorrect. Le compte n'a pas été supprimé.")
        else:
            st.warning("Impossible de supprimer le compte. Aucun compte connecté.")
