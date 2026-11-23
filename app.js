const express = require('express');
const mysql = require('mysql2');
const bcrypt = require('bcryptjs');
const session = require('express-session');
const path = require('path');

const app = express();

// Configuraciones básicas
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

app.use(session({
    secret: 'nexus_secreto_super_seguro',
    resave: false,
    saveUninitialized: false
}));

// Conexión a la base de datos en XAMPP
const db = mysql.createConnection({
    host: 'localhost',
    user: 'root',
    password: '',
    database: 'sistema_login'
});

db.connect((err) => {
    if (err) {
        console.error('Error conectando a MySQL:', err);
        return;
    }
    console.log('✅ Conectado a la base de datos sistema_login en XAMPP');
});

// --- RUTA DE REGISTRO ---
app.post('/register', async (req, res) => {
    const { nombre, correo, password } = req.body;

    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        const query = 'INSERT INTO usuarios (nombre, correo, password) VALUES (?, ?, ?)';

        db.query(query, [nombre, correo, hashedPassword], (err, result) => {
            if (err) {
                console.error(err);
                return res.send('Error al registrar el usuario. <a href="/register.html">Intentar de nuevo</a>');
            }
            // Te manda directo a iniciar sesión
            res.redirect('/login.html');
        });
    } catch (error) {
        console.error(error);
        res.status(500).send('Error en el servidor');
    }
});

// --- RUTA DE INICIO DE SESIÓN ---
app.post('/login', (req, res) => {
    const { correo, password } = req.body;

    const query = 'SELECT * FROM usuarios WHERE correo = ?';
    db.query(query, [correo], async (err, results) => {
        if (err) throw err;

        if (results.length === 0) {
            return res.send('Usuario no encontrado. <a href="/login.html">Inténtalo de nuevo</a>');
        }

        const usuario = results[0];
        const passwordMatch = await bcrypt.compare(password, usuario.password);

        if (passwordMatch) {
            req.session.loggedin = true;
            req.session.nombre = usuario.nombre;
            // Te manda directo a tu página principal de Nexus Gaming Lounge
            res.redirect('/');
        } else {
            res.send('Contraseña incorrecta. <a href="/login.html">Volver</a>');
        }
    });
});

// --- RUTA PARA CERRAR SESIÓN ---
app.get('/logout', (req, res) => {
    req.session.destroy(() => {
        res.redirect('/login.html');
    });
});

// Iniciar servidor
app.listen(3000, () => {
    console.log('🚀 Servidor corriendo en http://localhost:3000');
});