-- Création de la base de données
CREATE DATABASE IF NOT EXISTS gestion_users;

-- Utilisation de la base de données
USE gestion_users;

-- Création de la table utilisateurs
CREATE TABLE IF NOT EXISTS utilisateurs (
    id INT AUTO_INCREMENT PRIMARY KEY,
    nom VARCHAR(100) NOT NULL,
    prenom VARCHAR(100) NOT NULL,
    login VARCHAR(50) NOT NULL UNIQUE,
    password VARCHAR(100) NOT NULL,
    photo VARCHAR(255)
);

-- Création d'un utilisateur administrateur avec login="admin" et password="admin"
-- Mot de passe: admin (haché avec SHA1(MD5()))
INSERT INTO utilisateurs (nom, prenom, login, password, photo)
VALUES ('Admin', 'Super', 'admin', '4dd29ba2d33b84ad3674f529fcfbb4da7aba4f78', '');

-- Le mot de passe 'admin' est haché avec sha1(md5('admin'))
-- Vous pouvez vous connecter avec login: admin, password: admin