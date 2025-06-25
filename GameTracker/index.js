const express = require('express');
const cors = require('cors');
require('dotenv').config();
const axios = require('axios');
const sqlite3 = require('sqlite3').verbose();
const DBSOURCE = 'gametracker.db';
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const JWT_SECRET = process.env.JWT_SECRET || 'supersecretkey';
const fs = require('fs');
const nodemailer = require('nodemailer');
const cron = require('node-cron');
const path = require('path');
const ldap = require('ldapjs');

const app = express();
const PORT = process.env.PORT || 3000;

app.use(cors());
app.use(express.json());

// Request logging middleware
app.use((req, res, next) => {
  console.log(`[${new Date().toISOString()}] ${req.method} ${req.path} from ${req.ip || req.connection.remoteAddress}`);
  next();
});

// Initialize SQLite DB
const db = new sqlite3.Database(DBSOURCE, (err) => {
  if (err) {
    console.error('Could not connect to database', err);
  } else {
    db.run(`CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE,
      password TEXT,
      can_manage_users INTEGER DEFAULT 0,
      email TEXT,
      ntfy_topic TEXT,
      created_at TEXT,
      origin TEXT DEFAULT 'local',
<<<<<<< HEAD
      display_name TEXT
=======
      display_name TEXT,
      shares_library INTEGER DEFAULT 0
>>>>>>> master
    )`);
    db.run(`CREATE TABLE IF NOT EXISTS user_games (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER,
      game_id INTEGER,
      game_name TEXT,
      cover_url TEXT,
      release_date TEXT,
      status TEXT,
<<<<<<< HEAD
=======
      steam_app_id TEXT,
      last_price TEXT,
      last_price_updated TEXT,
>>>>>>> master
      UNIQUE(user_id, game_id),
      FOREIGN KEY(user_id) REFERENCES users(id)
    )`);
    // Add columns if missing (for migrations)
    db.run(`ALTER TABLE users ADD COLUMN origin TEXT DEFAULT 'local'`, () => {});
    db.run(`ALTER TABLE users ADD COLUMN display_name TEXT`, () => {});
<<<<<<< HEAD
=======
    db.run(`ALTER TABLE user_games ADD COLUMN steam_app_id TEXT`, () => {});
    db.run(`ALTER TABLE user_games ADD COLUMN last_price TEXT`, () => {});
    db.run(`ALTER TABLE user_games ADD COLUMN last_price_updated TEXT`, () => {});
>>>>>>> master
    console.log('Database initialized');
  }
});

// Ensure root user exists
const ensureRootUser = async () => {
  db.get('SELECT * FROM users WHERE username = ?', ['root'], async (err, user) => {
    if (!user) {
<<<<<<< HEAD
      const hash = await bcrypt.hash('Qq123456', 10);
=======
      const hash = await bcrypt.hash('', 10);
>>>>>>> master
      db.run(
        'INSERT INTO users (username, password, can_manage_users, origin, display_name) VALUES (?, ?, 1, ?, ?)',
        ['root', hash, 'local', 'root']
      );
      console.log('Root user created.');
    }
  });
};
ensureRootUser();

// Helper: get or create user
function getOrCreateUser(username, cb, opts = {}) {
  db.get('SELECT * FROM users WHERE username = ?', [username], (err, user) => {
    if (user) {
      // Optionally update display_name/origin if provided
      if (opts.display_name || opts.origin) {
        db.run('UPDATE users SET display_name = COALESCE(?, display_name), origin = COALESCE(?, origin) WHERE username = ?', [opts.display_name, opts.origin, username]);
      }
      return cb(null, user);
    }
    // Use CN if provided and non-empty, otherwise fallback to username
    const displayNameToUse = (typeof opts.display_name === 'string' && opts.display_name.trim() !== '' ? opts.display_name : username);
    console.log('Creating user:', { username, display_name: displayNameToUse, origin: opts.origin });
    db.run('INSERT INTO users (username, created_at, origin, display_name) VALUES (?, ?, ?, ?)', [username, new Date().toISOString(), opts.origin || 'local', displayNameToUse], function (err) {
      if (err) return cb(err);
      cb(null, { id: this.lastID, username, created_at: new Date().toISOString(), origin: opts.origin || 'local', display_name: displayNameToUse });
    });
  });
}

// Health check endpoint
app.get('/api/health', (req, res) => {
  // Check database connection
  db.get('SELECT COUNT(*) as count FROM users', [], (err, result) => {
    if (err) {
      console.error('[Health] Database error:', err);
      return res.status(500).json({ 
        status: 'error', 
        message: 'Database connection failed',
        error: err.message 
      });
    }
    
    // Check if root user exists
    db.get('SELECT id, username FROM users WHERE username = ?', ['root'], (err, rootUser) => {
      if (err) {
        console.error('[Health] Error checking root user:', err);
        return res.status(500).json({ 
          status: 'error', 
          message: 'Database error checking root user',
          error: err.message 
        });
      }
      
      res.json({ 
        status: 'ok',
        database: 'connected',
        totalUsers: result.count,
        rootUser: rootUser ? { id: rootUser.id, username: rootUser.username } : null,
        timestamp: new Date().toISOString()
      });
    });
  });
});

// Unified search endpoint: IGDB + RAWG
app.get('/api/games/search', async (req, res) => {
  const query = req.query.q;
  if (!query) {
    return res.status(400).json({ error: 'Missing search query' });
  }
  try {
    // IGDB request
    const igdbPromise = axios.post(
      'https://api.igdb.com/v4/games',
<<<<<<< HEAD
      `search "${query}"; fields id,name,first_release_date,cover.image_id; limit 10;`,
=======
      `search "${query}"; fields id,name,first_release_date,cover.image_id,external_games.category,external_games.uid; limit 10;`,
>>>>>>> master
      {
        headers: {
          'Client-ID': process.env.IGDB_CLIENT_ID,
          'Authorization': `Bearer ${process.env.IGDB_BEARER_TOKEN}`,
          'Accept': 'application/json',
        },
      }
<<<<<<< HEAD
    ).then(response => (response.data || []).map(game => ({
      id: 'igdb_' + game.id,
      name: game.name,
      releaseDate: game.first_release_date
        ? new Date(game.first_release_date * 1000).toISOString().split('T')[0]
        : null,
      coverUrl: game.cover?.image_id
        ? `https://images.igdb.com/igdb/image/upload/t_cover_big/${game.cover.image_id}.jpg`
        : null,
      source: 'igdb',
    }))).catch(() => []);
=======
    ).then(async response => {
      const games = response.data || [];
      // For each game, fetch external_games for Steam (category 1)
      return games.map(game => {
        let steamAppId = null;
        if (Array.isArray(game.external_games)) {
          const steamExternal = game.external_games.find(ext => ext.category === 1 && ext.uid);
          if (steamExternal) {
            steamAppId = steamExternal.uid;
          }
        }
        return {
          id: 'igdb_' + game.id,
          name: game.name,
          releaseDate: game.first_release_date
            ? new Date(game.first_release_date * 1000).toISOString().split('T')[0]
            : null,
          coverUrl: game.cover?.image_id
            ? `https://images.igdb.com/igdb/image/upload/t_cover_big/${game.cover.image_id}.jpg`
            : null,
          source: 'igdb',
          steamAppId,
        };
      });
    }).catch(() => []);
>>>>>>> master

    // RAWG request
    const rawgPromise = axios.get(
      'https://api.rawg.io/api/games',
      {
        params: {
          key: process.env.RAWG_API_KEY,
          search: query,
          page_size: 10,
        }
      }
<<<<<<< HEAD
    ).then(response => (response.data.results || []).map(game => ({
      id: 'rawg_' + game.id,
      name: game.name,
      releaseDate: game.released,
      coverUrl: game.background_image,
      source: 'rawg',
    }))).catch(() => []);
=======
    ).then(async response => {
      const games = response.data.results || [];
      // For each game, fetch detailed info to get Steam App ID
      const detailedGames = await Promise.all(games.map(async (game) => {
        let steamAppId = null;
        try {
          const detailRes = await axios.get(`https://api.rawg.io/api/games/${game.id}`, {
            params: { key: process.env.RAWG_API_KEY }
          });
          const stores = detailRes.data.stores || [];
          const steamStore = stores.find(s => s.store && s.store.id === 1 && s.url_en);
          if (steamStore && steamStore.url_en) {
            // Extract App ID from the Steam URL
            const match = steamStore.url_en.match(/\/app\/(\d+)/);
            if (match) {
              steamAppId = match[1];
            }
          }
        } catch (e) {
          // Ignore errors, just no steamAppId
        }
        return {
          id: 'rawg_' + game.id,
          name: game.name,
          releaseDate: game.released,
          coverUrl: game.background_image,
          source: 'rawg',
          steamAppId,
        };
      }));
      return detailedGames;
    }).catch(() => []);
>>>>>>> master

    // Wait for both
    const [igdbResults, rawgResults] = await Promise.all([igdbPromise, rawgPromise]);

    // Merge and deduplicate by name (case-insensitive)
    const seen = new Set();
<<<<<<< HEAD
    const merged = [...igdbResults, ...rawgResults].filter(game => {
=======
    const merged = [...igdbResults, ...rawgResults].map(game => {
      // If RAWG didn't provide a steamAppId, but IGDB did for the same game name, use IGDB's steamAppId
      if (!game.steamAppId) {
        const igdbMatch = igdbResults.find(igdbGame => igdbGame.name.toLowerCase() === game.name.toLowerCase() && igdbGame.steamAppId);
        if (igdbMatch) {
          return { ...game, steamAppId: igdbMatch.steamAppId };
        }
      }
      return game;
    }).filter(game => {
>>>>>>> master
      const key = game.name.toLowerCase();
      if (seen.has(key)) return false;
      seen.add(key);
      return true;
    });

    res.json(merged);
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch games from providers', details: error.message });
  }
});

<<<<<<< HEAD
=======
// Remove the in-memory cache for Steam prices
app.get('/api/game-price/:steamAppId', async (req, res) => {
  const { steamAppId } = req.params;
  if (!steamAppId) {
    return res.status(400).json({ error: 'Missing Steam App ID' });
  }
  try {
    const response = await axios.get(`https://store.steampowered.com/api/appdetails`, {
      params: {
        appids: steamAppId,
        cc: 'il', // Israeli store
        l: 'en',
      },
    });
    const data = response.data[steamAppId];
    if (!data.success) {
      return res.status(404).json({ error: 'Game not found on Steam' });
    }
    const priceOverview = data.data.price_overview;
    if (!priceOverview) {
      return res.status(404).json({ error: 'Price not available for this game' });
    }
    res.json({
      price: priceOverview.final_formatted,
      currency: priceOverview.currency,
      discount: priceOverview.discount_percent,
      original_price: priceOverview.initial_formatted,
    });
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch price from Steam', details: error.message });
  }
});

>>>>>>> master
// --- Notification Settings ---
const SETTINGS_FILE = 'settings.json';
function loadSettings() {
  try {
    return JSON.parse(fs.readFileSync(SETTINGS_FILE, 'utf8'));
  } catch {
    return { smtp: {}, ntfy: {}, ldap: {} };
  }
}
function saveSettings(settings) {
  try {
    fs.writeFileSync(SETTINGS_FILE, JSON.stringify(settings, null, 2), { flag: 'w' });
    console.log('settings.json created/updated.');
  } catch (err) {
    console.error('Failed to write settings.json:', err);
  }
}

// --- Notification Functions ---
async function sendEmail(subject, text, toOverride) {
  const { smtp } = loadSettings();
<<<<<<< HEAD
  if (!smtp.host || !smtp.port || !smtp.from || !smtp.to) {
    console.log('SMTP settings incomplete, not sending email.');
    return;
  }
=======
  if (!smtp.host || !smtp.port || !smtp.from) {
    console.log('[Email] SMTP settings incomplete:', { host: smtp.host, port: smtp.port, from: smtp.from });
    return;
  }

  // Log the email destination decision process
  console.log('[Email] Determining recipient:', {
    userProvidedEmail: toOverride,
    settingsDefaultEmail: smtp.to,
    fallbackEmail: process.env.DEFAULT_EMAIL
  });

  const finalRecipient = toOverride || smtp.to || process.env.DEFAULT_EMAIL;
  if (!finalRecipient) {
    console.log('[Email] No recipient email found, skipping email send');
    return;
  }

  console.log('[Email] Will send email to:', finalRecipient);

>>>>>>> master
  const options = {
    host: smtp.host,
    port: Number(smtp.port),
    secure: Number(smtp.port) === 465,
  };
  if (smtp.user && smtp.pass) {
    options.auth = { user: smtp.user, pass: smtp.pass };
  }
<<<<<<< HEAD
  const transporter = nodemailer.createTransport(options);
  try {
    console.log('Attempting to send email:', { to: toOverride || (smtp && smtp.to) || process.env.DEFAULT_EMAIL, subject });
    await transporter.sendMail({
      from: smtp.from,
      to: toOverride || (smtp && smtp.to) || process.env.DEFAULT_EMAIL,
      subject,
      text,
    });
    console.log('Email sent successfully.');
  } catch (err) {
    console.error('Email error:', err);
  }
}
=======

  console.log('[Email] SMTP Configuration:', {
    host: options.host,
    port: options.port,
    secure: options.secure,
    hasAuth: !!options.auth
  });

  const transporter = nodemailer.createTransport(options);
  try {
    const result = await transporter.sendMail({
      from: smtp.from,
      to: finalRecipient,
      subject,
      text,
    });
    console.log('[Email] Successfully sent email:', {
      messageId: result.messageId,
      recipient: finalRecipient,
      subject: subject
    });
  } catch (err) {
    console.error('[Email] Failed to send email:', {
      error: err.message,
      recipient: finalRecipient,
      subject: subject
    });
    throw err;  // Re-throw to let caller handle the error
  }
}

>>>>>>> master
async function sendNtfy(title, message, topicOverride) {
  const { ntfy } = loadSettings();
  if (!ntfy.url || !ntfy.topic) return;
  await axios.post(`${ntfy.url.replace(/\/$/, '')}/${topicOverride || (ntfy && ntfy.topic) || process.env.DEFAULT_NTFY_TOPIC}`, message, {
    headers: { Title: title },
  });
}

<<<<<<< HEAD
=======
// --- LDAP Email Lookup ---
async function getLdapEmail(username) {
  return new Promise((resolve) => {
    const settings = loadSettings();
    const ldapSettings = settings.ldap || {};
    
    if (!ldapSettings.url || !ldapSettings.bindDn || !ldapSettings.bindPass) {
      resolve(null);
      return;
    }
    
    const client = ldap.createClient({ url: ldapSettings.url });
    client.bind(ldapSettings.bindDn, ldapSettings.bindPass, (err) => {
      if (err) {
        console.log('[LDAP] Service account bind failed for email lookup:', err);
        client.unbind();
        resolve(null);
        return;
      }
      
      const searchOptions = {
        filter: `(sAMAccountName=${username})`,
        scope: 'sub',
        attributes: ['mail', 'email']
      };
      
      client.search(ldapSettings.base, searchOptions, (err, searchRes) => {
        if (err) {
          console.log('[LDAP] Search failed for email lookup:', err);
          client.unbind();
          resolve(null);
          return;
        }
        
        let foundEmail = null;
        searchRes.on('searchEntry', (entry) => {
          const attributes = {};
          entry.attributes.forEach(attr => {
            attributes[attr.type] = attr.vals.length === 1 ? attr.vals[0] : attr.vals;
          });
          foundEmail = attributes.mail || attributes.email || null;
        });
        
        searchRes.on('end', () => {
          client.unbind();
          resolve(foundEmail);
        });
        
        searchRes.on('error', (err) => {
          console.error('[LDAP] Search error during email lookup:', err);
          client.unbind();
          resolve(null);
        });
      });
    });
  });
}

// --- Notification Triggers ---
async function notifyEvent(type, game, username, status) {
  let subject, text, title, message;
  if (type === 'add') {
    subject = `Game added: ${game.gameName}`;
    text = `User ${username} added "${game.gameName}" to their library.`;
    title = 'Game Added';
    message = `User ${username} added "${game.gameName}" to their library.`;
  } else if (type === 'status') {
    subject = `Game status changed: ${game.gameName}`;
    text = `User ${username} changed status of "${game.gameName}" to ${status}.`;
    title = 'Game Status Changed';
    message = `User ${username} changed status of "${game.gameName}" to ${status}.`;
  } else if (type === 'release') {
    subject = `Game released: ${game.gameName}`;
    text = `"${game.gameName}" has been released!`;
    title = 'Game Released';
    message = `"${game.gameName}" has been released!`;
  }
  
  // First try to get email from database
  db.get('SELECT email, ntfy_topic FROM users WHERE username = ?', [username], async (err, userRow) => {
    if (err) {
      console.error('Error fetching user details:', err);
      return;
    }
    
    let userEmail = userRow && userRow.email;
    const userNtfy = userRow && userRow.ntfy_topic;
    
    // If no email in database, try LDAP
    if (!userEmail) {
      console.log('No email found in database for user:', username, 'trying LDAP...');
      try {
        userEmail = await getLdapEmail(username);
        if (userEmail) {
          console.log('Found email from LDAP:', userEmail);
          // Update the database with the LDAP email
          db.run('UPDATE users SET email = ? WHERE username = ?', [userEmail, username]);
        }
      } catch (ldapErr) {
        console.error('Error getting email from LDAP:', ldapErr);
      }
    }
    
    // Try to send email
    try {
      console.log('Attempting to send email to:', userEmail);
      await sendEmail(subject, text, userEmail);
      console.log('Email sent successfully');
    } catch (emailErr) {
      console.error('Error sending email:', emailErr);
    }
    
    // Try to send ntfy
    try {
      await sendNtfy(title, message, userNtfy);
      console.log('Ntfy notification sent successfully');
    } catch (ntfyErr) {
      console.error('Error sending ntfy:', ntfyErr);
    }
  });
}

>>>>>>> master
// --- Settings API ---
app.get('/api/settings', (req, res) => {
  res.json(loadSettings());
});
app.post('/api/settings', express.json(), (req, res) => {
  console.log('POST /api/settings called');
  console.log('Received settings:', req.body);
  try {
    saveSettings(req.body);
    res.json({ success: true });
  } catch (err) {
    console.error('Error in /api/settings:', err);
    res.status(500).json({ error: 'Failed to save settings.' });
  }
});

<<<<<<< HEAD
// --- Notification Triggers ---
async function notifyEvent(type, game, username, status) {
  let subject, text, title, message;
  if (type === 'add') {
    subject = `Game added: ${game.gameName}`;
    text = `User ${username} added "${game.gameName}" to their library.`;
    title = 'Game Added';
    message = `You added "${game.gameName}" to your library.`;
  } else if (type === 'status') {
    subject = `Game status changed: ${game.gameName}`;
    text = `User ${username} changed status of "${game.gameName}" to ${status}.`;
    title = 'Game Status Changed';
    message = `Status of "${game.gameName}" changed to ${status}.`;
  } else if (type === 'release') {
    subject = `Game released: ${game.gameName}`;
    text = `"${game.gameName}" has been released!`;
    title = 'Game Released';
    message = `"${game.gameName}" has been released!`;
  }
  // Fetch user email/ntfy_topic
  db.get('SELECT email, ntfy_topic FROM users WHERE username = ?', [username], async (err, userRow) => {
    const userEmail = userRow && userRow.email ? userRow.email : undefined;
    const userNtfy = userRow && userRow.ntfy_topic ? userRow.ntfy_topic : undefined;
    try { await sendEmail(subject, text, userEmail); } catch {}
    try { await sendNtfy(title, message, userNtfy); } catch {}
  });
}

// --- Add/update a game status for a user (with notification) ---
app.post('/api/user/:username/games', async (req, res) => {
  const { username } = req.params;
  let { gameId, gameName, coverUrl, releaseDate, status } = req.body;
=======
// --- Add/update a game status for a user (with notification) ---
app.post('/api/user/:username/games', async (req, res) => {
  const { username } = req.params;
  let { gameId, gameName, coverUrl, releaseDate, status, steamAppId } = req.body;
>>>>>>> master
  if (!gameId || !gameName || !status) {
    return res.status(400).json({ error: 'Missing required fields' });
  }
  // If no releaseDate, always set status to 'unreleased'
  if (!releaseDate) {
    status = 'unreleased';
  }
  getOrCreateUser(username, async (err, user) => {
    if (err) return res.status(500).json({ error: 'DB error' });
    db.get('SELECT * FROM user_games WHERE user_id = ? AND game_id = ?', [user.id, gameId], async (err, row) => {
      let eventType = 'add';
      if (row) {
        if (row.status !== status) eventType = 'status';
        if (row.status === 'unreleased' && status !== 'unreleased' && releaseDate && new Date(releaseDate) <= new Date()) {
          await notifyEvent('release', { gameName }, username, status);
        }
      }
      db.run(
<<<<<<< HEAD
        `INSERT INTO user_games (user_id, game_id, game_name, cover_url, release_date, status)
         VALUES (?, ?, ?, ?, ?, ?)
         ON CONFLICT(user_id, game_id) DO UPDATE SET status=excluded.status`,
        [user.id, gameId, gameName, coverUrl, releaseDate, status],
=======
        `INSERT INTO user_games (user_id, game_id, game_name, cover_url, release_date, status, steam_app_id)
         VALUES (?, ?, ?, ?, ?, ?, ?)
         ON CONFLICT(user_id, game_id) DO UPDATE SET status=excluded.status, steam_app_id=excluded.steam_app_id`,
        [user.id, gameId, gameName, coverUrl, releaseDate, status, steamAppId],
>>>>>>> master
        async function (err) {
          if (err) return res.status(500).json({ error: 'DB error' });
          await notifyEvent(eventType, { gameName }, username, status);
          res.json({ success: true });
        }
      );
    });
  });
});

// Get all games for a user
app.get('/api/user/:username/games', (req, res) => {
  const { username } = req.params;
  getOrCreateUser(username, (err, user) => {
    if (err) return res.status(500).json({ error: 'DB error' });
    db.all('SELECT * FROM user_games WHERE user_id = ?', [user.id], (err, rows) => {
      if (err) return res.status(500).json({ error: 'DB error' });
<<<<<<< HEAD
      res.json(rows);
=======
      // Ensure steamAppId is included in the response
      const mapped = rows.map(row => ({
        ...row,
        steamAppId: row.steam_app_id || null
      }));
      res.json(mapped);
>>>>>>> master
    });
  });
});

// Remove a game from a user's list
app.delete('/api/user/:username/games/:gameId', (req, res) => {
  const { username, gameId } = req.params;
  if (!username || !gameId) {
    return res.status(400).json({ error: 'Missing username or gameId' });
  }
  getOrCreateUser(username, (err, user) => {
    if (err) return res.status(500).json({ error: 'DB error' });
    db.run(
      'DELETE FROM user_games WHERE user_id = ? AND game_id = ?',
      [user.id, gameId],
      function (err) {
        if (err) return res.status(500).json({ error: 'DB error' });
        res.json({ success: true });
      }
    );
  });
});

// --- Auth Middleware ---
function authRequired(req, res, next) {
  const auth = req.headers.authorization;
  if (!auth || !auth.startsWith('Bearer ')) return res.status(401).json({ error: 'Unauthorized' });
  try {
    const payload = jwt.verify(auth.slice(7), JWT_SECRET);
    req.user = payload;
    next();
  } catch {
    return res.status(401).json({ error: 'Invalid token' });
  }
}
function requirePermission(permission) {
  return (req, res, next) => {
    if (!req.user || !req.user[permission]) {
      return res.status(403).json({ error: 'Forbidden' });
    }
    next();
  };
}

// --- Auth Endpoints ---
app.post('/api/auth/login', (req, res) => {
  const { username, password } = req.body;
  const settings = loadSettings();
  const ldapSettings = settings.ldap || {};

  function fallbackLocalAuth() {
    console.log('[Auth] Using fallback local authentication for user:', username);
    db.get('SELECT * FROM users WHERE username = ?', [username], async (err, user) => {
      if (err) {
        console.error('[Auth] Database error during user lookup:', err);
        return res.status(500).json({ error: 'Database error' });
      }
      if (!user) {
        console.log('[Auth] Local user not found:', username);
        return res.status(401).json({ error: 'Invalid credentials' });
      }
      console.log('[Auth] Found user in database:', { id: user.id, username: user.username });
      try {
        const valid = await bcrypt.compare(password, user.password);
        if (!valid) {
          console.log('[Auth] Local password validation failed for user:', username);
          return res.status(401).json({ error: 'Invalid credentials' });
        }
        console.log('[Auth] Password validation successful for user:', username);
        const token = jwt.sign({
          id: user.id,
          username: user.username,
          can_manage_users: !!user.can_manage_users,
          origin: user.origin || 'local',
          display_name: user.display_name || user.username
        }, JWT_SECRET, { expiresIn: '12h' });
        res.json({ token });
      } catch (bcryptError) {
        console.error('[Auth] Error during password comparison:', bcryptError);
        return res.status(500).json({ error: 'Authentication error' });
      }
    });
  }

  // Check if LDAP is properly configured with all required fields
  const isLdapConfigured = ldapSettings.url && 
                          ldapSettings.base && 
                          ldapSettings.bindDn && 
                          ldapSettings.bindPass &&
                          ldapSettings.url.trim() !== '' &&
                          ldapSettings.base.trim() !== '' &&
                          ldapSettings.bindDn.trim() !== '' &&
                          ldapSettings.bindPass.trim() !== '';

  // If LDAP is not properly configured, use local auth immediately
  if (!isLdapConfigured) {
    console.log('[Auth] LDAP not properly configured. Using local authentication.');
    return fallbackLocalAuth();
  }

  // If LDAP is enabled with a service account, use the reliable search-then-bind method.
  try {
    const client = ldap.createClient({ url: ldapSettings.url });

    // 1. Bind as service account
    client.bind(ldapSettings.bindDn, ldapSettings.bindPass, (err) => {
      if (err) {
        console.log('[LDAP] Service account bind failed:', err);
        client.unbind();
        return fallbackLocalAuth();
      }
      console.log('[LDAP] Service account bind succeeded.');

      // 2. Search for the user by sAMAccountName
      const searchOptions = {
        filter: `(sAMAccountName=${username})`,
        scope: 'sub',
<<<<<<< HEAD
        attributes: ['dn', 'memberOf', 'displayName', 'cn']
=======
        attributes: ['dn', 'memberOf', 'displayName', 'cn', 'mail', 'email']
>>>>>>> master
      };
      console.log(`[LDAP] Searching for user with filter: ${searchOptions.filter}`);

      client.search(ldapSettings.base, searchOptions, (err, searchRes) => {
        if (err) {
          console.log('[LDAP] Search initiation failed:', err);
          client.unbind();
          return fallbackLocalAuth();
        }

        let foundUser = null;
        searchRes.on('searchEntry', (entry) => {
          console.log('[LDAP] Raw search entry received:', entry.toString());

          // Manually construct the user object from the entry's properties.
          // This is more reliable than the .object getter.
          const attributes = {};
          entry.attributes.forEach(attr => {
            attributes[attr.type] = attr.vals.length === 1 ? attr.vals[0] : attr.vals;
          });
          
          foundUser = {
            dn: entry.dn.toString(),
            ...attributes
          };
          console.log('[LDAP] Successfully parsed user object:', JSON.stringify(foundUser, null, 2));
        });

        searchRes.on('error', (err) => {
          console.error('[LDAP] Search error during processing:', err.message);
          client.unbind();
          return fallbackLocalAuth();
        });

        searchRes.on('end', (result) => {
          console.log('[LDAP] Search finished. Result status:', result ? result.status : 'N/A');
          if (!foundUser) {
            console.log('[LDAP] User object was not populated from search. This could be a permissions issue or the user truly does not exist in the search base.');
            client.unbind();
            return fallbackLocalAuth();
          }

          const userDn = foundUser.dn;
          console.log(`[LDAP] Found user's correct DN: ${userDn}`);

          // 3. Authenticate as the found user (verifies their password)
          client.bind(userDn, password, (err) => {
            if (err) {
              console.log('[LDAP] User password authentication failed:', err);
              client.unbind();
              return fallbackLocalAuth(); // Incorrect password for this user
            }
            console.log('[LDAP] User password authentication succeeded.');

            // 4. Check group membership (Authorization)
            if (ldapSettings.requiredGroup) {
                const memberOf = foundUser.memberOf || [];
                const groups = Array.isArray(memberOf) ? memberOf : [memberOf];
                console.log('[LDAP] User is member of groups:', groups);

                const isMember = groups.some(group =>
                    group.toLowerCase() === ldapSettings.requiredGroup.toLowerCase() ||
                    group.toLowerCase().includes(`cn=${ldapSettings.requiredGroup.toLowerCase()}`)
                );

                if (!isMember) {
                    console.log(`[LDAP] Authorization failed: User is not in required group '${ldapSettings.requiredGroup}'.`);
                    client.unbind();
                    return res.status(403).json({ error: 'Not a member of the required group' });
                }
                console.log('[LDAP] Authorization passed: Group membership check OK.');
            }

            // 5. User is authenticated and authorized, create token.
            client.unbind();
            // Try to get CN from attribute, else extract from DN
            let cnValue = Array.isArray(foundUser.cn) ? foundUser.cn[0] : foundUser.cn;
            if (!cnValue && foundUser.dn) {
              // Extract CN from DN string
              const match = foundUser.dn.match(/CN=([^,]+)/i);
              if (match) cnValue = match[1];
            }
            const displayName = (typeof cnValue === 'string' && cnValue.trim() !== '') ? cnValue : username;
            
<<<<<<< HEAD
            console.log('[DEBUG] Extracted cnValue:', cnValue);
            console.log('[DEBUG] Final displayName:', displayName);

            getOrCreateUser(username, (err, user) => {
              if (err) return res.status(500).json({ error: 'DB error' });
              // Update display_name and origin for LDAP users
              db.run('UPDATE users SET display_name = ?, origin = ? WHERE username = ?', [displayName, 'ldap', username]);
=======
            // Get email from LDAP attributes
            const userEmail = foundUser.mail || foundUser.email || null;
            
            console.log('[DEBUG] Extracted cnValue:', cnValue);
            console.log('[DEBUG] Final displayName:', displayName);
            console.log('[DEBUG] User email from LDAP:', userEmail);

            getOrCreateUser(username, (err, user) => {
              if (err) return res.status(500).json({ error: 'DB error' });
              // Update display_name, origin, and email for LDAP users
              const updates = ['display_name = ?, origin = ?'];
              const params = [displayName, 'ldap'];
              
              if (userEmail) {
                updates.push('email = ?');
                params.push(userEmail);
              }
              
              params.push(username);
              db.run(`UPDATE users SET ${updates.join(', ')} WHERE username = ?`, params);
              
>>>>>>> master
              const token = jwt.sign({
                id: user.id,
                username: user.username,
                can_manage_users: !!user.can_manage_users,
                origin: 'ldap',
                display_name: displayName
              }, JWT_SECRET, { expiresIn: '12h' });
              res.json({ token });
            }, { origin: 'ldap', display_name: displayName });
          });
        });
      });
    });
  } catch (ldapError) {
    console.error('[LDAP] Error creating LDAP client:', ldapError);
    return fallbackLocalAuth();
  }
});

// --- User Management Endpoints ---
// Create user (admin only)
app.post('/api/users', authRequired, requirePermission('can_manage_users'), (req, res) => {
<<<<<<< HEAD
  const { username, password, can_manage_users = 0, email = '', ntfy_topic = '' } = req.body;
  if (!username || !password) return res.status(400).json({ error: 'Missing username or password' });
  bcrypt.hash(password, 10).then(hash => {
    db.run(
      'INSERT INTO users (username, password, can_manage_users, email, ntfy_topic, created_at, origin, display_name) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
      [username, hash, can_manage_users ? 1 : 0, email, ntfy_topic, new Date().toISOString(), 'local', username],
=======
  const { username, password, can_manage_users = 0, email = '', ntfy_topic = '', shares_library = 0 } = req.body;
  if (!username || !password) return res.status(400).json({ error: 'Missing username or password' });
  bcrypt.hash(password, 10).then(hash => {
    db.run(
      'INSERT INTO users (username, password, can_manage_users, email, ntfy_topic, created_at, origin, display_name, shares_library) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)',
      [username, hash, can_manage_users ? 1 : 0, email, ntfy_topic, new Date().toISOString(), 'local', username, shares_library ? 1 : 0],
>>>>>>> master
      function (err) {
        if (err) return res.status(400).json({ error: 'User already exists' });
        res.json({ success: true, id: this.lastID });
      }
    );
  });
});

// List users (manager only)
app.get('/api/users', authRequired, requirePermission('can_manage_users'), (req, res) => {
<<<<<<< HEAD
  db.all('SELECT id, username, can_manage_users, email, ntfy_topic, created_at, origin, display_name FROM users', [], (err, rows) => {
=======
  db.all('SELECT id, username, can_manage_users, email, ntfy_topic, created_at, origin, display_name, shares_library FROM users', [], (err, rows) => {
>>>>>>> master
    if (err) return res.status(500).json({ error: 'DB error' });
    res.json(rows);
  });
});

// Edit user (manager only)
app.put('/api/users/:id', authRequired, requirePermission('can_manage_users'), (req, res) => {
  const { id } = req.params;
<<<<<<< HEAD
  const { password, can_manage_users, email, ntfy_topic } = req.body;
=======
  const { password, can_manage_users, email, ntfy_topic, shares_library } = req.body;
>>>>>>> master
  const updates = [];
  const params = [];
  if (typeof can_manage_users !== 'undefined') {
    updates.push('can_manage_users = ?');
    params.push(can_manage_users ? 1 : 0);
  }
  if (typeof email !== 'undefined') {
    updates.push('email = ?');
    params.push(email);
  }
  if (typeof ntfy_topic !== 'undefined') {
    updates.push('ntfy_topic = ?');
    params.push(ntfy_topic);
  }
<<<<<<< HEAD
=======
  if (typeof shares_library !== 'undefined') {
    updates.push('shares_library = ?');
    params.push(shares_library ? 1 : 0);
  }
>>>>>>> master
  if (password) {
    bcrypt.hash(password, 10).then(hash => {
      updates.push('password = ?');
      params.push(hash);
      params.push(id);
      db.run(`UPDATE users SET ${updates.join(', ')} WHERE id = ?`, params, function (err) {
        if (err) return res.status(500).json({ error: 'DB error' });
        res.json({ success: true });
      });
    });
  } else {
    params.push(id);
    db.run(`UPDATE users SET ${updates.join(', ')} WHERE id = ?`, params, function (err) {
      if (err) return res.status(500).json({ error: 'DB error' });
      res.json({ success: true });
    });
  }
});

// Delete user (manager only)
app.delete('/api/users/:id', authRequired, requirePermission('can_manage_users'), (req, res) => {
  const { id } = req.params;
  db.run('DELETE FROM users WHERE id = ?', [id], function (err) {
    if (err) return res.status(500).json({ error: 'DB error' });
    res.json({ success: true });
  });
});

// --- Per-user settings endpoint ---
// Authenticated user can update their own email/ntfy_topic
app.put('/api/user/me/settings', authRequired, (req, res) => {
  const userId = req.user.id;
  const { email, ntfy_topic } = req.body;
  const updates = [];
  const params = [];
  if (typeof email !== 'undefined') {
    updates.push('email = ?');
    params.push(email);
  }
  if (typeof ntfy_topic !== 'undefined') {
    updates.push('ntfy_topic = ?');
    params.push(ntfy_topic);
  }
  if (updates.length === 0) {
    return res.status(400).json({ error: 'No settings to update' });
  }
  params.push(userId);
  db.run(`UPDATE users SET ${updates.join(', ')} WHERE id = ?`, params, function (err) {
    if (err) return res.status(500).json({ error: 'DB error' });
    res.json({ success: true });
  });
});

<<<<<<< HEAD
=======
// --- Per-user sharing toggle endpoint ---
// Authenticated user can update their own shares_library
app.put('/api/user/me/sharing', authRequired, (req, res) => {
  const userId = req.user.id;
  const { shares_library } = req.body;
  if (typeof shares_library === 'undefined') {
    return res.status(400).json({ error: 'Missing shares_library value' });
  }
  db.run('UPDATE users SET shares_library = ? WHERE id = ?', [shares_library ? 1 : 0, userId], function (err) {
    if (err) return res.status(500).json({ error: 'DB error' });
    res.json({ success: true });
  });
});

// --- List all users who share their library ---
app.get('/api/shared-libraries', authRequired, (req, res) => {
  db.all('SELECT id, username, display_name, origin FROM users WHERE shares_library = 1', [], (err, rows) => {
    if (err) return res.status(500).json({ error: 'DB error' });
    res.json(rows);
  });
});

>>>>>>> master
// --- Scheduled Notifications for Unreleased Games ---
const SENT_NOTIFICATIONS_FILE = path.join(__dirname, 'sent_notifications.json');
let sentNotifications = {};
if (fs.existsSync(SENT_NOTIFICATIONS_FILE)) {
  try {
    sentNotifications = JSON.parse(fs.readFileSync(SENT_NOTIFICATIONS_FILE, 'utf8'));
  } catch {
    sentNotifications = {};
  }
}
function markNotificationSent(username, gameId, type) {
  if (!sentNotifications[username]) sentNotifications[username] = {};
  if (!sentNotifications[username][gameId]) sentNotifications[username][gameId] = {};
<<<<<<< HEAD
  sentNotifications[username][gameId][type] = true;
=======
  sentNotifications[username][gameId][type] = new Date().toISOString();
>>>>>>> master
  fs.writeFileSync(SENT_NOTIFICATIONS_FILE, JSON.stringify(sentNotifications, null, 2));
}
function wasNotificationSent(username, gameId, type) {
  return sentNotifications[username] && sentNotifications[username][gameId] && sentNotifications[username][gameId][type];
}
function getAllUsers(cb) {
  db.all('SELECT username FROM users', [], (err, rows) => {
    if (err) return cb(err);
    cb(null, rows.map(r => r.username));
  });
}
function getUserGames(username, cb) {
  getOrCreateUser(username, (err, user) => {
    if (err) return cb(err);
    db.all('SELECT * FROM user_games WHERE user_id = ?', [user.id], (err, rows) => {
      if (err) return cb(err);
      cb(null, rows);
    });
  });
}
async function sendReleaseReminder(username, game, days) {
  let when = days === 0 ? 'today' : `in ${days} days`;
  let subject = `Reminder: "${game.game_name}" releases ${when}!`;
  let text = `The game "${game.game_name}" you are following releases ${when} (${game.release_date}).`;
  let title = 'Game Release Reminder';
  let message = text;
<<<<<<< HEAD
  await sendEmail(subject, text);
  await sendNtfy(title, message);
}
=======
  
  // Get user's email from database or LDAP
  const userEmail = await getUserEmail(username);
  if (userEmail) {
    await sendEmail(subject, text, userEmail);
  }
  
  // Get user's ntfy topic and send notification
  db.get('SELECT ntfy_topic FROM users WHERE username = ?', [username], async (err, userRow) => {
    const userNtfy = userRow && userRow.ntfy_topic ? userRow.ntfy_topic : undefined;
    if (userNtfy) {
      await sendNtfy(title, message, userNtfy);
    }
  });
}

// Helper function to get user email from LDAP if not in database
async function getUserEmail(username) {
  return new Promise((resolve) => {
    db.get('SELECT email FROM users WHERE username = ?', [username], async (err, userRow) => {
      if (err || !userRow || !userRow.email) {
        // Try to get email from LDAP
        const ldapEmail = await getLdapEmail(username);
        if (ldapEmail) {
          // Update database with LDAP email
          db.run('UPDATE users SET email = ? WHERE username = ?', [ldapEmail, username]);
        }
        resolve(ldapEmail);
      } else {
        resolve(userRow.email);
      }
    });
  });
}

>>>>>>> master
console.log('About to schedule cron job');
cron.schedule('0 8 * * *', () => {
  console.log('[CRON] Running scheduled notification check...');
  getAllUsers((err, users) => {
    if (err) return console.error('Error fetching users for notifications:', err);
    users.forEach(username => {
      getUserGames(username, (err, games) => {
        if (err) return;
        let found = false;
        games.forEach(game => {
          if (game.status === 'unreleased' && game.release_date) {
            const releaseDate = new Date(game.release_date);
            const today = new Date();
            today.setHours(0,0,0,0);
            releaseDate.setHours(0,0,0,0);
            const diffDays = Math.ceil((releaseDate - today) / (1000 * 60 * 60 * 24));
            console.log(`[CRON] User: ${username}, Game: ${game.game_name}, Release: ${game.release_date}, diffDays: ${diffDays}`);
            let type = null;
            if (diffDays === 30) type = '30days';
            if (diffDays === 7) type = '7days';
            if (diffDays === 0) type = 'release';
            if (type && !wasNotificationSent(username, game.game_id, type)) {
              console.log(`[CRON] Sending ${type} reminder to ${username} for game ${game.game_name}`);
              sendReleaseReminder(username, game, diffDays).then(() => {
                markNotificationSent(username, game.game_id, type);
                console.log(`Sent ${type} release reminder to ${username} for game ${game.game_name}`);
<<<<<<< HEAD
              });
              found = true;
=======
              }).catch(err => {
                console.error(`Failed to send ${type} reminder to ${username} for game ${game.game_name}:`, err);
              });
              found = true;
            } else if (type && wasNotificationSent(username, game.game_id, type)) {
              console.log(`[CRON] Notification already sent for ${username}, game ${game.game_name}, type ${type}`);
>>>>>>> master
            }
          }
        });
        if (!found) {
          console.log(`[CRON] No matching unreleased games for user ${username}`);
        }
      });
    });
  });
});

<<<<<<< HEAD
// --- Shared Lists Feature ---
const sharedLists = [];

// Share a user's list with one or more users
app.post('/api/user/:username/share', async (req, res) => {
  const { username } = req.params;
  const { toUsers } = req.body;
  if (!Array.isArray(toUsers) || toUsers.length === 0) return res.status(400).json({ error: 'No users to share with.' });
  // Remove existing shares to these users
  for (const toUser of toUsers) {
    const idx = sharedLists.findIndex(s => s.from_user === username && s.to_user === toUser);
    if (idx !== -1) sharedLists.splice(idx, 1);
  }
  // Add new shares
  for (const toUser of toUsers) {
    sharedLists.push({ from_user: username, to_user: toUser, shared_at: new Date().toISOString() });
  }
  res.json({ success: true });
});

// Get lists shared with the current user
app.get('/api/user/:username/shared-with-me', async (req, res) => {
  const { username } = req.params;
  const shares = sharedLists.filter(s => s.to_user === username);
  res.json(shares);
});

// Get a specific user's shared list (read-only)
app.get('/api/user/:username/shared/:fromUser', async (req, res) => {
  const { fromUser } = req.params;
  getUserGames(fromUser, (err, games) => {
    if (err) return res.status(500).json({ error: 'DB error' });
    res.json(games);
=======
// --- Per-user Library Sharing (persistent) ---
const ensureUserShareTable = () => {
  db.run(`CREATE TABLE IF NOT EXISTS user_shares (
    from_user TEXT,
    to_user TEXT,
    shared_at TEXT,
    PRIMARY KEY (from_user, to_user),
    FOREIGN KEY (from_user) REFERENCES users(username),
    FOREIGN KEY (to_user) REFERENCES users(username)
  )`);
};
ensureUserShareTable();

// Share a user's list with one or more users
app.post('/api/user/:username/share', authRequired, (req, res) => {
  const { username } = req.params;
  const { toUsers } = req.body;
  if (req.user.username !== username) return res.status(403).json({ error: 'You can only share your own library.' });
  if (!Array.isArray(toUsers)) return res.status(400).json({ error: 'No users to share with.' });
  // Remove all existing shares for this user
  db.run('DELETE FROM user_shares WHERE from_user = ?', [username], (err) => {
    if (err) return res.status(500).json({ error: 'DB error' });
    // Add new shares
    if (toUsers.length === 0) return res.json({ success: true });
    const now = new Date().toISOString();
    const stmt = db.prepare('INSERT OR IGNORE INTO user_shares (from_user, to_user, shared_at) VALUES (?, ?, ?)');
    toUsers.forEach(toUser => {
      stmt.run(username, toUser, now);
    });
    stmt.finalize((err) => {
      if (err) return res.status(500).json({ error: 'DB error' });
      res.json({ success: true });
    });
  });
});

// Get lists shared with the current user
app.get('/api/user/:username/shared-with-me', authRequired, (req, res) => {
  const { username } = req.params;
  if (req.user.username !== username) return res.status(403).json({ error: 'You can only view your own shares.' });
  db.all('SELECT from_user, shared_at FROM user_shares WHERE to_user = ?', [username], (err, rows) => {
    if (err) return res.status(500).json({ error: 'DB error' });
    res.json(rows);
  });
});

// Get a specific user's shared list (read-only, only if shared with you)
app.get('/api/user/:username/shared/:fromUser', authRequired, (req, res) => {
  const { username, fromUser } = req.params;
  if (req.user.username !== username) return res.status(403).json({ error: 'You can only view your own shares.' });
  db.get('SELECT 1 FROM user_shares WHERE from_user = ? AND to_user = ?', [fromUser, username], (err, row) => {
    if (err) return res.status(500).json({ error: 'DB error' });
    if (!row) return res.status(403).json({ error: 'Not shared with you.' });
    getUserGames(fromUser, (err, games) => {
      if (err) return res.status(500).json({ error: 'DB error' });
      res.json(games);
    });
>>>>>>> master
  });
});

// Revoke a share from a user
<<<<<<< HEAD
app.delete('/api/user/:username/revoke-share/:fromUser', async (req, res) => {
  const { username, fromUser } = req.params;
  const idx = sharedLists.findIndex(s => s.from_user === fromUser && s.to_user === username);
  if (idx !== -1) sharedLists.splice(idx, 1);
  res.json({ success: true });
=======
app.delete('/api/user/:username/revoke-share/:fromUser', authRequired, (req, res) => {
  const { username, fromUser } = req.params;
  if (req.user.username !== username) return res.status(403).json({ error: 'You can only revoke your own shares.' });
  db.run('DELETE FROM user_shares WHERE from_user = ? AND to_user = ?', [fromUser, username], function (err) {
    if (err) return res.status(500).json({ error: 'DB error' });
    res.json({ success: true });
  });
});

// List all users (for sharing UI, not just admins)
app.get('/api/all-users', authRequired, (req, res) => {
  db.all('SELECT username, display_name, origin FROM users', [], (err, rows) => {
    if (err) return res.status(500).json({ error: 'DB error' });
    res.json(rows);
  });
});

// Get the list of users I am sharing with
app.get('/api/user/:username/share', authRequired, (req, res) => {
  const { username } = req.params;
  if (req.user.username !== username) return res.status(403).json({ error: 'You can only view your own shares.' });
  db.all('SELECT to_user FROM user_shares WHERE from_user = ?', [username], (err, rows) => {
    if (err) return res.status(500).json({ error: 'DB error' });
    res.json({ toUsers: rows.map(r => r.to_user) });
  });
});

// --- Scheduled Weekly Price Update for User Libraries ---
cron.schedule('0 3 * * 1', async () => { // Every Monday at 3:00 AM
  console.log('[CRON] Starting weekly Steam price update for all user libraries...');
  db.all('SELECT * FROM user_games WHERE steam_app_id IS NOT NULL', [], async (err, games) => {
    if (err) {
      console.error('[CRON] Failed to fetch user games for price update:', err);
      return;
    }
    for (const game of games) {
      try {
        const response = await axios.get('https://store.steampowered.com/api/appdetails', {
          params: {
            appids: game.steam_app_id,
            cc: 'il',
            l: 'en',
          },
        });
        const data = response.data[game.steam_app_id];
        if (data && data.success && data.data && data.data.price_overview) {
          const price = data.data.price_overview.final_formatted;
          db.run('UPDATE user_games SET last_price = ?, last_price_updated = ? WHERE id = ?', [
            price,
            new Date().toISOString(),
            game.id
          ], (err) => {
            if (err) {
              console.error(`[CRON] Failed to update price for game_id ${game.game_id} (user_game id ${game.id}):`, err);
            } else {
              console.log(`[CRON] Updated price for game_id ${game.game_id} (user_game id ${game.id}): ${price}`);
            }
          });
        } else {
          console.log(`[CRON] No price found for Steam app_id ${game.steam_app_id} (game_id ${game.game_id})`);
        }
      } catch (err) {
        console.error(`[CRON] Error fetching price for Steam app_id ${game.steam_app_id} (game_id ${game.game_id}):`, err.message);
      }
    }
    console.log('[CRON] Weekly Steam price update complete.');
  });
>>>>>>> master
});

app.listen(PORT, '0.0.0.0', () => {
  console.log(`Server running on port ${PORT}`);
<<<<<<< HEAD
});
=======
});
>>>>>>> master
