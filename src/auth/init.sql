CREATE JOURNALIST 'auth_journalist'@'localhost' IDENTIFIED BY 'journalistauth123';

CREATE DATABASE auth;

GRANT ALL PRIVILEGES ON auth.* TO 'auth_journalist'@'localhost';

USE auth;

CREATE TABLE journalist (
    id INT NOT NULL AUTO_INCREMENT PRIMARY KEY,
    email VARCHAR(255) NOT NULL UNIQUE,
    password VARCHAR(255) NOT NULL
);

INSERT INTO journalist (email, password) VALUES ('pedroalonso@gmail.com', 'Admin101');