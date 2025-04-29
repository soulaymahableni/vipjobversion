const express = require("express");
const exphbs = require("express-handlebars");
const socketIO = require('socket.io');
const bodyParser = require("body-parser");
const mysql = require("mysql2");
const axios = require('axios');
const nodemailer = require("nodemailer");
const crypto = require("crypto");
const path = require("path");
const session = require("express-session"); // Pour gérer les sessions
const { engine } = require("express-handlebars");
const scrapeTanitJobs = require("./scrape-tanitjobs");
const twilio = require('twilio');
const PDFDocument = require('pdfkit');
const multer = require('multer');
const { format, addMonths } = require('date-fns');
require('dotenv').config();
const cors = require('cors');
const port = 3001;
const http = require('http');
const { title } = require("process");

const app = express();
const server = http.createServer(app);
const io = socketIO(server, {
  cors: {
    origin: "*",
    methods: ["GET", "POST"]
  }
});

app.engine(
  "hbs",
  exphbs.engine({
    extname: "hbs",
    defaultLayout: "main",
    layoutsDir: path.join(__dirname, "views", "layouts"),
    partialsDir: path.join(__dirname, "views", "partials"),
    helpers: require("handlebars-layouts"), // Assurez-vous que le helper est bien inclus
  })
);

app.set("view engine", "hbs");
app.set("views", path.join(__dirname, "views")); // Assurez-vous que ce chemin est correct

app.use(express.static('public'));
app.use(cors());

app.use(express.json());
app.use('/uploads', express.static('uploads'));

// Store io in app locals so you can access it in routes
app.locals.io = io;

// ✅ Client connection log
io.on("connection", (socket) => {
  console.log("✅ Un client WebSocket est connecté :", socket.id);

  socket.on("disconnect", () => {
    console.log("❌ Client déconnecté :", socket.id);
  });
});

// Configuration de la base de données
const db = mysql.createConnection({
  host: "localhost",
  user: "root",
  password: "", // Mot de passe de votre base de données
  database: "vipjob", // Nom de la base de données
});

// Middleware to parse JSON bodies
app.use(express.json());

// WebSocket connection handler
io.on('connection', (socket) => {
  console.log('A user connected');
  socket.on('disconnect', () => {
    console.log('User disconnected');
  });
});
// Connexion à la base de données
db.connect((err) => {
  if (err) {
    console.error("Erreur de connexion à la base de données:", err);
  } else {
    console.log("Connecté à la base de données MySQL");
  }
});

// Middleware pour parser les requêtes JSON et les données de formulaire
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

// Configuration des sessions
app.use(
  session({
    secret: "votre_clé_secrète", // Clé secrète pour signer les cookies de session
    resave: false,
    saveUninitialized: true,
    cookie: { secure: false }, // À mettre à `true` si vous utilisez HTTPS
  })
);

// Configuration de Nodemailer pour envoyer des e-mails
const transporter = nodemailer.createTransport({
  host: "mail.itqanlabs.com",
  port: 587,
  secure: false,
  auth: {
    user: "vipjob-project@itqanlabs.com",
    pass: "JNLFWgG0A9QYNq2",
  },
  tls: {
    rejectUnauthorized: false,
  },
});

// Vérification de la connexion SMTP
transporter.verify((error, success) => {
  if (error) {
    console.error("Erreur de connexion SMTP :", error);
  } else {
    console.log("Serveur SMTP prêt à envoyer des e-mails");
  }
});

const twilioClient = twilio(
  process.env.TWILIO_ACCOUNT_SID,
  process.env.TWILIO_AUTH_TOKEN
);

// Route pour gérer la connexion
app.post("/login", (req, res) => {
  const { email, password } = req.body;

  // Vérifier si l'utilisateur existe dans la base de données
  db.query("SELECT * FROM utilisateur WHERE email = ?", [email], (err, results) => {
    if (err) {
      console.error("Erreur lors de la vérification de l'e-mail:", err);
      return res.status(500).json({ success: false, message: "Erreur serveur" });
    }
    if (results.length === 0) {
      return res.status(400).json({ success: false, message: "Cet e-mail n'est pas enregistré." });
    }

    // Vérifier le mot de passe
    const hashedPassword = crypto.createHash("sha256").update(password).digest("hex");
    if (hashedPassword !== results[0].mot_de_passe) {
      return res.status(400).json({ success: false, message: "Mot de passe incorrect." });
    }

    // Si tout est correct, créer une session pour l'utilisateur
    req.session.user = {
      id: results[0].id,
      email: results[0].email,
      role: results[0].role_id,
    };

    // Renvoyer une réponse de succès
    res.status(200).json({ success: true, data: results });
  });
});


app.get("/reset-password", (req, res) => {
  res.render("user/reset-password");
});
// Route pour la page de tableau de bord
app.get("/profile", (req, res) => {
  // Vérifier si l'utilisateur est connecté
  if (!req.session.user) {
    return res.redirect("/login"); // Rediriger vers la page de connexion si l'utilisateur n'est pas connecté
  }
  app.get("/abonnement", (req, res) => {
    res.render("user/abonnement");
  });
  // Afficher la page de tableau de bord
  res.render("user/profile", { title: "Tableau de bord - VipJob.tn", user: req.session.user });
});

// Route pour gérer la déconnexion
app.get("/logout", (req, res) => {
  // Détruire la session
  req.session.destroy((err) => {
    if (err) {
      console.error("Erreur lors de la déconnexion:", err);
      return res.status(500).json({ success: false, message: "Erreur lors de la déconnexion" });
    }
    res.redirect("/login"); // Rediriger vers la page de connexion
  });
});

// Route pour gérer l'inscription
app.post("/signup", (req, res) => {
  const { prenom, nom, email, telephone, password, confirmPassword, gouvernorat } = req.body;

  // Vérifier que les mots de passe correspondent
  if (password !== confirmPassword) {
    return res.status(400).json({ success: false, message: "Les mots de passe ne correspondent pas." });
  }

  // Vérifier que tous les champs sont remplis
  if (!prenom || !nom || !email || !telephone || !password || !gouvernorat) {
    return res.status(400).json({ success: false, message: "Tous les champs sont obligatoires." });
  }

  // Vérifier que l'e-mail n'existe pas déjà
  db.query("SELECT * FROM utilisateur WHERE email = ?", [email], (err, results) => {
    if (err) {
      console.error("Erreur lors de la vérification de l'e-mail:", err);
      return res.status(500).json({ success: false, message: "Erreur serveur" });
    }
    if (results.length > 0) {
      return res.status(400).json({ success: false, message: "Cet e-mail est déjà utilisé." });
    }

    // Générer un code de confirmation
    const confirmationCode = crypto.randomBytes(3).toString("hex").toUpperCase();

    // Hacher le mot de passe (pour la sécurité)
    const hashedPassword = crypto.createHash("sha256").update(password).digest("hex");

    // Insérer l'utilisateur dans la base de données
    const query =
      "INSERT INTO utilisateur (nom, prenom, email, mot_de_passe, numero_telephone, role_id, etat, etat_email, code_email, gouvernorat) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)";
    const values = [nom, prenom, email, hashedPassword, telephone, 3, 1, 0, confirmationCode, gouvernorat];

    db.query(query, values, (err, results) => {
      if (err) {
        console.error("Erreur lors de l'inscription:", err);
        return res.status(500).json({ success: false, message: "Erreur lors de l'inscription" });
      }

      // Envoyer un e-mail de confirmation
      const mailOptions = {
        from: "vipjob-project@itqanlabs.com",
        to: email,
        subject: "Confirmation d'inscription - VipJob.tn",
        text: `Bonjour ${prenom},\n\nVotre code de confirmation est : ${confirmationCode}\n\nMerci de vous inscrire sur VipJob.tn.`,
      };

      transporter.sendMail(mailOptions, (err, info) => {
        if (err) {
          console.error("Erreur lors de l'envoi de l'e-mail:", err);
          return res.status(500).json({ success: false, message: "Erreur lors de l'envoi de l'e-mail de confirmation" });
        }
        console.log("E-mail envoyé:", info.response);
        res.status(200).json({ success: true, message: "Inscription réussie. Vérifiez votre e-mail pour le code de confirmation." });
      });
    });
  });
});

// Route pour vérifier le code de confirmation
app.post("/verify", (req, res) => {
  const { email, code } = req.body; // Récupérer l'e-mail et le code du formulaire

  // Vérifier si le code correspond à celui dans la base de données
  db.query(
    "SELECT * FROM utilisateur WHERE email = ? AND code_email = ?",
    [email, code],
    (err, results) => {
      if (err) {
        console.error("Erreur lors de la vérification du code:", err);
        return res.status(500).json({ success: false, message: "Erreur serveur" });
      }
      if (results.length === 0) {
        return res.status(400).json({ success: false, message: "Code de confirmation invalide." });
      }

      // Si le code est valide, marquer l'utilisateur comme vérifié
      db.query(
        "UPDATE utilisateur SET etat_email = 1 WHERE email = ?",
        [email],
        (err, results) => {
          if (err) {
            console.error("Erreur lors de la mise à jour de l'utilisateur:", err);
            return res.status(500).json({ success: false, message: "Erreur lors de la vérification" });
          }
          res.status(200).json({ success: true, message: "Compte vérifié avec succès !" });
        }
      );
    }
  );
});

// Route pour la page d'accueil
app.get("/", (req, res) => {
  res.render("user/home", { title: "Accueil - VipJob.tn" });
});
app.get("/jobs", (req, res) => {
  res.render("jobs", { title: "Jobs - VipJob.tn" });
});
app.get("/favorite-offres", (req, res) => {
  res.render("offre/favorite-offres", { title: "Offres favorites - VipJob.tn" });
});




// Route pour la page d'inscription
app.get("/signup", (req, res) => {
  res.render("user/signup", { title: "Inscription - VipJob.tn" });
});

// Route pour la page de vérification
app.get('/verify', (req, res) => {
  res.render('user/verify', { title: "Vérification - VipJob.tn" });
});
// Route pour la page des offres
app.get("/offre", (req, res) => {
  res.render("user/offre", { title: "Offres - VipJob.tn" });
});
app.get("/users", (req, res) => {
  res.render("admin/users", { title: "Offres - VipJob.tn" });
});
app.get("/offres", (req, res) => {
  res.render("admin/offres", { title: "Offres - VipJob.tn" });
});

app.get("/index", (req, res) => {
  res.render("user/index", { title: "Index - VipJob.tn" });
});

// Route pour la page de profil
app.get("/profile", (req, res) => {
  res.render("user/profile", { title: "Profil - VipJob.tn" });
});


// Route pour la page de connexion
app.get("/login", (req, res) => {
  res.render("user/login", { title: "Connexion - VipJob.tn" });
});

//route contact:
app.get('/contact', (req, res) => {
  res.render("user/contact",{ title: "contact - VipJob.tn" });
});
// Route pour la page "Mot de passe oublié"
app.get("/forgot-password", (req, res) => {
  res.render("user/forgot-password", { title: "Mot de passe oublié - VipJob.tn" });
});

// Route pour traiter la soumission du formulaire "Mot de passe oublié"
app.post("/forgot-password", (req, res) => {
  const { email } = req.body;

  // Vérifier si l'e-mail existe dans la base de données
  db.query("SELECT * FROM utilisateur WHERE email = ?", [email], (err, results) => {
    if (err) {
      console.error("Erreur lors de la vérification de l'e-mail:", err);
      return res.status(500).json({ success: false, message: "Erreur serveur" });
    }
    if (results.length === 0) {
      return res.status(400).json({ success: false, message: "Cet e-mail n'est pas enregistré." });
    }

    // Générer un token de réinitialisation
    const resetToken = crypto.randomBytes(20).toString("hex");

    // Enregistrer le token dans la base de données
    db.query(
      "UPDATE utilisateur SET reset_token = ? WHERE email = ?",
      [resetToken, email],
      (err, results) => {
        if (err) {
          console.error("Erreur lors de la génération du token:", err);
          return res.status(500).json({ success: false, message: "Erreur lors de la génération du token" });
        }

        // Envoyer un e-mail avec le lien de réinitialisation
        const resetLink = `http://localhost:3001/reset-password?token=${resetToken}`;
        const mailOptions = {
          from: "vipjob-project@itqanlabs.com",
          to: email,
          subject: "Réinitialisation de mot de passe - VipJob.tn",
          text: `Bonjour,\n\nPour réinitialiser votre mot de passe, cliquez sur ce lien : ${resetLink}\n\nSi vous n'avez pas demandé cette réinitialisation, ignorez cet e-mail.`,
        };

        transporter.sendMail(mailOptions, (err, info) => {
          if (err) {
            console.error("Erreur lors de l'envoi de l'e-mail:", err);
            return res.status(500).json({ success: false, message: "Erreur lors de l'envoi de l'e-mail de réinitialisation" });
          }
          console.log("E-mail envoyé:", info.response);

          return res.render("user/login", { title: "Connexion - VipJob.tn" });
        });
      }
    );
  });
});

app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());

// Simulated database
const users = [
  {
    id: 1,
    email: 'user@example.com',
    password: '$2a$10$...', // Hashed password
    resetToken: '543ebf23fd2b7b7e3cb235673ea06dd81ea8eaf5', // Example token
  },
];

// Simuler une base de données (remplacez par votre vraie base de données)
const user = [
  { id: 1, email: 'user@example.com', password: '$2a$10$...' } // Mot de passe hashé
];

// Endpoint pour réinitialiser le mot de passe
app.post('/reset-password', (req, res) => {
  const { token, password } = req.body;

  // Vérifier si le token est valide
  db.query('SELECT * FROM utilisateur WHERE reset_token = ?', [token], (err, results) => {
    if (err) {
      console.error('Erreur lors de la recherche de l\'utilisateur:', err);
      return res.status(500).json({ message: 'Erreur serveur' });
    }

    if (results.length === 0) {
      return res.status(400).json({ message: 'Token invalide ou expiré.' });
    }

    const user = results[0];

    // Hacher le nouveau mot de passe
    const hashedPassword = crypto.createHash('sha256').update(password).digest('hex');

    // Mettre à jour le mot de passe et effacer le token
    db.query(
      'UPDATE utilisateur SET mot_de_passe = ?, reset_token = NULL WHERE id = ?',
      [hashedPassword, user.id],
      (err, results) => {
        if (err) {
          console.error('Erreur lors de la mise à jour du mot de passe:', err);
          return res.status(500).json({ message: 'Erreur serveur' });
        }
        res.json({ message: 'Mot de passe réinitialisé avec succès.' });
      }
    );
  });
});

//profil

// Dans votre fichier server.js (Node.js/Express)
app.get('/profil/:id', (req, res) => {
  const userId = req.params.id;

  db.query(
    `SELECT nom, prenom, email, numero_telephone AS telephone, gouvernorat, domaine 
     FROM utilisateur WHERE id = ?`,
    [userId],
    (err, result) => {
      if (err) return res.status(500).json({ error: err.message });
      if (result.length === 0) return res.status(404).json({ error: "Utilisateur non trouvé" });

      res.json(result[0]);
    }
  );
});

// Route POST pour enregistrer un profil
app.post("/profil/:id", (req, res) => {
  let userId = req.params.id;

  // Générer un ID si c'est un nouvel utilisateur
  if (userId === "nouvel_utilisateur") {
    userId = generateUniqueUserId(); // Fonction à créer pour générer un ID unique
  }

  const {
    prenom, nom, email, telephone, domaine,
    experience, diplome, gouvernorat, bio, skills, langues
  } = req.body;

  const sql = `
    INSERT INTO utilisateur (id, prenom, nom, email, numero_telephone, domaine, experience, diplome, gouvernorat, bio, skills, langues)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    ON DUPLICATE KEY UPDATE 
      prenom = VALUES(prenom), nom = VALUES(nom), email = VALUES(email), 
      numero_telephone = VALUES(numero_telephone), domaine = VALUES(domaine), 
      experience = VALUES(experience), diplome = VALUES(diplome), gouvernorat = VALUES(gouvernorat),
      bio = VALUES(bio), skills = VALUES(skills), langues = VALUES(langues);
  `;

  const values = [
    userId, prenom, nom, email, telephone, domaine,
    experience, diplome, gouvernorat, bio,
    JSON.stringify(Array.isArray(skills) && skills.length ? skills : []),
    JSON.stringify(langues || [])
  ];

  db.query(sql, values, (err, result) => {
    if (err) {
      console.error("Erreur SQL:", err.sqlMessage);
      return res.status(500).json({ error: "Erreur base de données", details: err.sqlMessage });
    }

    // Return the updated domain in the response
    res.json({
      success: true,
      message: "Profil mis à jour ou créé avec succès",
      userId,
      domaine // Include the domain in the response
    });
  });
});

// Nouvelle route pour générer le PDF
const upload = multer({ dest: 'uploads/' });

app.post('/api/generate-cv', upload.single('photo'), (req, res) => {
  try {
    const data = req.body;
    const photoPath = req.file ? req.file.path : null;

    if (!data.prenom || !data.nom) {
      return res.status(400).json({ error: "Prénom et nom requis" });
    }

    const doc = new PDFDocument({ size: 'A4', margin: 50 });

    res.setHeader('Content-Type', 'application/pdf');
    res.setHeader('Content-Disposition', `attachment; filename="CV_${data.prenom}_${data.nom}.pdf"`);

    doc.pipe(res);

    // 🔵 Bannière Bleue
    doc.rect(0, 0, doc.page.width, 100).fill('#1E88E5'); // Couleur bleu
    doc.fillColor('white').fontSize(24).font('Helvetica-Bold').text(`${data.prenom} ${data.nom}`, { align: 'center' });
    doc.fontSize(16).text('INFORMATIQUE', { align: 'center' });
    doc.moveDown(2);
    doc.fillColor('black'); // Revenir à la couleur noire

    // 🖼️ Ajout de la photo
    if (photoPath) {
      doc.image(photoPath, { fit: [100, 100], align: 'center', valign: 'top' });
      doc.moveDown(2);
    }

    // 📌 Fonctions utilitaires
    const drawSectionTitle = (title) => {
      doc.fontSize(14).font('Helvetica-Bold').text(title);
      doc.moveDown(0.5);
      doc.moveTo(50, doc.y).lineTo(550, doc.y).stroke(); // Ligne horizontale
      doc.moveDown(0.5);
    };

    const drawText = (text) => {
      doc.fontSize(12).font('Helvetica').text(text);
      doc.moveDown();
    };

    // 📍 Coordonnées
    drawSectionTitle('Coordonnées');
    drawText(`Email: ${data.email || 'Non spécifié'}`);
    drawText(`Téléphone: ${data.telephone || 'Non spécifié'}`);
    drawText(`Gouvernorat: ${data.gouvernorat || 'Non spécifié'}`);

    // 📍 À propos de moi
    drawSectionTitle('À propos de moi');
    drawText(data.bio?.trim() || "Pas d'informations disponibles");

    // 🎓 Formation
    drawSectionTitle('Formation');
    drawText(data.formation || 'Non spécifiée');

    // 🏆 Expérience
    drawSectionTitle('Expérience');
    drawText(data.experience || 'Débutant (0-1 an)');

    // 🔧 Compétences
    drawSectionTitle('Compétences');
    drawText((data.skills || []).join('\n• ') || 'Aucune');

    // 🗣️ Langues
    drawSectionTitle('Langues');
    drawText((data.langues || []).join('\n• ') || 'Aucune');

    doc.end();

    // 🗑️ Supprimer l'image après génération
    if (photoPath) {
      setTimeout(() => fs.unlink(photoPath, (err) => { if (err) console.error(err); }), 5000);
    }

  } catch (error) {
    console.error('Erreur génération PDF:', error);
    res.status(500).json({ error: "Erreur interne", details: error.message });
  }
});

// Route pour s'abonner
app.post('/abonnement/subscribe', (req, res) => {
  const { duration, price } = req.body;
  const userId = req.session.user.id;
  const dateDeDebut = new Date();
  const dateDeFin = new Date();

  // Calcul de la date de fin selon la durée de l'abonnement (en mois)
  dateDeFin.setMonth(dateDeDebut.getMonth() + duration);

  const abonnementData = {
    id_utilisateur: userId,
    date_debut: dateDeDebut.toISOString().split('T')[0], // Format YYYY-MM-DD
    date_fin: dateDeFin.toISOString().split('T')[0],
    montant: price,
    type_abonnement: duration === 1 ? 'Mensuel' : (duration === 3 ? 'Trimestriel' : 'Annuel')
  };

  // Insérer dans la table 'abonnement'
  const query = 'INSERT INTO abonnement SET ?';
  db.query(query, abonnementData, (err, result) => {
    if (err) {
      console.error('Erreur lors de l\'abonnement:', err);
      return res.status(500).json({ success: false, message: 'Erreur lors de l\'abonnement' });
    }
    res.status(200).json({ success: true, message: 'Abonnement réussi' });
  });
});


// Fonction de hachage du mot de passe avec `crypto`
const hashPassword = (password) => {
  return crypto.createHash("sha256").update(password).digest("hex");
};

app.post('/create-user', (req, res) => {
  const { prenom, nom, email, password, telephone, gouvernorat } = req.body;

  if (!password) {
    return res.status(400).json({ success: false, message: 'Password is required' });
  }

  // Vérifier si l'email existe déjà
  const checkEmailSql = `SELECT id FROM utilisateur WHERE email = ?`;
  db.query(checkEmailSql, [email], (err, results) => {
    if (err) {
      console.error('Erreur lors de la vérification de l\'email:', err);
      return res.status(500).json({ success: false, message: 'Internal server error' });
    }

    if (results.length > 0) {
      return res.status(400).json({ success: false, message: 'Email already exists' });
    }

    // Hash du mot de passe
    const hashedPassword = hashPassword(password);

    // SQL query pour ajouter l'utilisateur
    const sql = `
      INSERT INTO utilisateur (prenom, nom, email, mot_de_passe, numero_telephone, gouvernorat)
      VALUES (?, ?, ?, ?, ?, ?)
    `;
    const values = [prenom, nom, email, hashedPassword, telephone, gouvernorat];

    db.query(sql, values, (err, result) => {
      if (err) {
        console.error('Erreur lors de l\'insertion de l\'utilisateur:', err);
        return res.status(500).json({ success: false, message: 'Internal server error' });
      }

      res.status(201).json({
        success: true,
        message: 'User created successfully',
        userId: result.insertId
      });
    });
  });
});

// Function to delete a user
const deleteUser = (email, callback) => {
  const query = "DELETE FROM utilisateur WHERE email = ?";
  db.query(query, [email], callback);
};

// Function to display a user by email or user_id
const displayUser = (callback) => {
  const query = "SELECT * FROM utilisateur";
  db.query(query, callback);
};

// Delete user
app.delete('/delete-user/:id', (req, res) => {
  const { id } = req.params;

  if (!id) {
    return res.status(400).json({ success: false, message: "L'id est obligatoire." });
  }

  const query = `DELETE FROM utilisateur WHERE id = ?`;

  db.query(query, [id], (err, results) => {
    if (err) {
      console.error("Erreur lors de la suppression de l'utilisateur:", err);
      return res.status(500).json({ success: false, message: "Erreur lors de la suppression de l'utilisateur." });
    }

    if (results.affectedRows === 0) {
      return res.status(404).json({ success: false, message: "Aucun utilisateur trouvé avec cet id user." });
    }

    res.status(200).json({ success: true, message: "Utilisateur supprimé avec succès." });
  });
});

// Display user
app.get('/display-user', (req, res) => {
  displayUser((err, results) => {
    if (results.length === 0) {
      return res.status(404).json({ success: false, message: "Aucun utilisateur trouvé avec cet email." });
    }

    res.status(200).json({ success: true, user: results });
  });
});

// Function to update user details
const updateUser = (email, prenom, nom, telephone, gouvernorat, callback) => {
  const query = `
    UPDATE utilisateur
    SET prenom = ?, nom = ?, numero_telephone = ?, gouvernorat = ?
    WHERE email = ?`;
  const values = [prenom, nom, telephone, gouvernorat, email];

  db.query(query, values, callback);
};
// Update user
app.put('/update-user', (req, res) => {
  const { email, prenom, nom, telephone, gouvernorat, id } = req.body;

  if (!email || !prenom || !nom || !telephone || !gouvernorat) {
    return res.status(400).json({ success: false, message: "Tous les champs sont obligatoires." });
  }

  const query = `
    UPDATE utilisateur
    SET prenom = ?, nom = ?, numero_telephone = ?, gouvernorat = ?, email = ?
    WHERE id = ?`;

  db.query(query, [prenom, nom, telephone, gouvernorat, email, id], (err, results) => {
    if (err) {
      console.error("Erreur lors de la mise à jour de l'utilisateur:", err);
      return res.status(500).json({ success: false, message: "Erreur lors de la mise à jour de l'utilisateur." });
    }

    res.status(200).json({ success: true, message: "Utilisateur mis à jour avec succès." });
  });
});

app.post('/create-offre', upload.single('image'), (req, res) => {
  const { titre, description, date_creation, date_fin, domaine, type_contrat, localisation, nb_candidat, status } = req.body;
  const image = req.file ? req.file.filename : null;

  const sql = `
    INSERT INTO offreemploi (titre, description, date_creation, date_fin, domaine, type_contrat, localisation, nb_candidat, status, image)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `;
  const values = [titre, description, date_creation, date_fin, domaine, type_contrat, localisation, nb_candidat, status, image];

  db.query(sql, values, (err, result) => {
    if (err) {
      console.error('Erreur lors de l\'insertion de l\'offre:', err);
      return res.status(500).json({ success: false, message: 'Internal server error' });
    }

    res.status(201).json({ 
      success: true, 
      message: 'Offre créée avec succès', 
      offreId: result.insertId 
    });
  });
});


app.get('/display-offres', (req, res) => {
  const query = "SELECT * FROM offreemploi";

  db.query(query, (err, results) => {
    if (err) {
      console.error("Erreur lors de la récupération des offres:", err);
      return res.status(500).json({ success: false, message: "Internal server error" });
    }

    res.status(200).json({ success: true, offres: results });
  });
});

app.get('/search-offre', (req, res) => {
  let query = "SELECT * FROM offreemploi WHERE 1 = 1";
  const params = [];

  if (req.query.titre) {
    query += " AND (titre LIKE ?)";
    params.push(`%${req.query.titre}%`);
  }

  if (req.query.domaine) {
    query += " AND domaine = ?";
    params.push(req.query.domaine);
  }

  if (req.query.type_contrat) {
    query += " AND type_contrat = ?";
    params.push(req.query.type_contrat);
  }

  if (req.query.localisation) {  // Fixed incorrect parameter check
    query += " AND localisation = ?";
    params.push(req.query.localisation);
  }

  db.query(query, params, (err, results) => {
    if (err) {
      console.error("Erreur lors de la récupération des offres:", err);
      return res.status(500).json({ success: false, message: "Internal server error" });
    }
    res.status(200).json({ success: true, offres: results });
  });
});

app.put('/update-offre/:id', (req, res) => {
  const id = req.params.id;  // Correct access to the id parameter
  const { titre, description, date_creation, date_fin, domaine, type_contrat, localisation, nb_candidat } = req.body;

  if (!id || !titre || !description || !date_creation || !date_fin || !domaine || !type_contrat || !localisation || !nb_candidat) {
    return res.status(400).json({ success: false, message: "Tous les champs sont obligatoires." });
  }

  const query = `
    UPDATE offreemploi
    SET titre = ?, description = ?, date_creation = ?, date_fin = ?, domaine = ?, type_contrat = ?, localisation = ?, nb_candidat = ?
    WHERE id = ?
  `;
  const values = [titre, description, date_creation, date_fin, domaine, type_contrat, localisation, nb_candidat, id];

  db.query(query, values, (err, results) => {
    if (err) {
      console.error("Erreur lors de la mise à jour de l'offre:", err);
      return res.status(500).json({ success: false, message: "Erreur lors de la mise à jour de l'offre." });
    }

    if (results.affectedRows === 0) {
      return res.status(404).json({ success: false, message: "Aucune offre trouvée avec cet ID." });
    }

    res.status(200).json({ success: true, message: "Offre mise à jour avec succès." });
  });
});

app.delete('/delete-offre/:id', async (req, res) => {
  const { id } = req.params;

  if (!id) {
    return res.status(400).json({ success: false, message: "L'id de l'offre est obligatoire." });
  }

  const query = "DELETE FROM offreemploi WHERE id = ?";

  db.query(query, [id], (err, results) => {
    if (err) {
      console.error("Erreur lors de la suppression de l'offre:", err);
      return res.status(500).json({ success: false, message: "Erreur lors de la suppression de l'offre." });
    }

    if (results.affectedRows === 0) {
      return res.status(404).json({ success: false, message: "Aucune offre trouvée avec cet id." });
    }

    res.status(200).json({ success: true, message: "Offre supprimée avec succès." });
  });
});

// Browse Jobs functionality
app.get("/jobs", async (req, res) => {
  try {
    const jobs = await scrapeTanitJobs();
    res.json(jobs);
  } catch (error) {
    console.error("Error scraping jobs:", error);
    res.status(500).json({ error: error.message });
  }
});

// Get job details
app.get("/jobs/:id", async (req, res) => {
  try {
    const jobId = req.params.id;
    const jobs = await scrapeTanitJobs();
    const job = jobs.find(j => j.id === jobId);

    if (!job) {
      return res.status(404).json({ error: "Job not found" });
    }

    res.json(job);
  } catch (error) {
    console.error("Error fetching job details:", error);
    res.status(500).json({ error: error.message });
  }
});

// Search jobs
app.get("/jobs/search", async (req, res) => {
  try {
    const { query, location, type } = req.query;
    const jobs = await scrapeTanitJobs();

    let filteredJobs = jobs;

    if (query) {
      filteredJobs = filteredJobs.filter(job =>
        job.title.toLowerCase().includes(query.toLowerCase()) ||
        job.description.toLowerCase().includes(query.toLowerCase())
      );
    }

    if (location) {
      filteredJobs = filteredJobs.filter(job =>
        job.location.toLowerCase().includes(location.toLowerCase())
      );
    }

    if (type) {
      filteredJobs = filteredJobs.filter(job =>
        job.type.toLowerCase().includes(type.toLowerCase())
      );
    }

    res.json(filteredJobs);
  } catch (error) {
    console.error("Error searching jobs:", error);
    res.status(500).json({ error: error.message });
  }
});

// Get job categories
app.get("/jobs/categories", async (req, res) => {
  try {
    const jobs = await scrapeTanitJobs();
    const categories = [...new Set(jobs.map(job => job.category))];
    res.json(categories);
  } catch (error) {
    console.error("Error fetching categories:", error);
    res.status(500).json({ error: error.message });
  }
});

// Get jobs by category
app.get("/jobs/category/:category", async (req, res) => {
  try {
    const category = req.params.category;
    const jobs = await scrapeTanitJobs();
    const filteredJobs = jobs.filter(job => job.category === category);
    res.json(filteredJobs);
  } catch (error) {
    console.error("Error fetching jobs by category:", error);
    res.status(500).json({ error: error.message });
  }
});

app.get("/users-for-sms", (req, res) => {
  db.query("SELECT id, nom, numero_telephone,email FROM utilisateur", (err, results) => {
    if (err) {
      console.error("Erreur lors de la récupération des utilisateurs:", err);
      return res.status(500).json({ success: false });
    }
    res.json({ success: true, users: results });
  });
});
app.post("/send-sms", (req, res) => {
  const { numbers, offreTitle, email } = req.body;

  console.log("Received request:", req.body);

  if (!Array.isArray(numbers) || numbers.length === 0) {
    return res.status(400).json({ success: false, message: "Aucun numéro sélectionné." });
  }

  const validNumbers = numbers
    .map(num => {
      let trimmed = num.phone.trim();
      if (!trimmed.startsWith('+')) {
        trimmed = '+216' + trimmed;
      }
      return trimmed;
    })
    .filter(num => /^\+216\d{8}$/.test(num));

  if (validNumbers.length === 0) {
    return res.status(400).json({ success: false, message: "Numéros invalides." });
  }

  console.log("Valid phone numbers:", validNumbers);
  console.log("Offer title:", offreTitle);

  const parts = offreTitle.split(',').map(p => p.trim());

  const offreTitleExtracted = parts[0] || '';
  const offreDomaineExtracted = parts[1] || '';
  const offreTypeExtracted = parts[2] || '';

  let offreLocationExtracted = '';
  let offreStartDateExtracted = '';
  let offreEndDateExtracted = '';

  if (parts.length >= 4) {
    const fourthPart = parts[3];
    const fourthSplit = fourthPart.split(' ');
    if (fourthSplit.length >= 2) {
      offreStartDateExtracted = new Date(fourthSplit.pop()).toLocaleDateString('fr-FR');
      offreLocationExtracted = fourthSplit.join(' ');
    } else {
      offreLocationExtracted = fourthPart;
    }
  }

  if (parts.length >= 5) {
    offreEndDateExtracted = new Date(parts[4]).toLocaleDateString('fr-FR');
  }

  // Send email
  const mailOptions = {
    from: "vipjob-project@itqanlabs.com",
    to: numbers[0].email,
    subject: "📢 Nouvelle offre publiée sur VipJob",
    text: `Bonjour,\n\nUne nouvelle offre vient d'être publiée :\n\n
           🧑‍💻 Titre: ${offreTitleExtracted}\n
           📚 Domaine: ${offreDomaineExtracted}\n
           📝 Type: ${offreTypeExtracted}\n
           📍 Lieu: ${offreLocationExtracted}\n
           📅 Début: ${offreStartDateExtracted}\n
           📆 Fin: ${offreEndDateExtracted}\n\n
           Cordialement,\nL'équipe VipJob.tn`
  };

  transporter.sendMail(mailOptions, (err, info) => {
    if (err) {
      console.error("Email sending error:", err);
    } else {
      console.log("Email sent successfully:", info.response);
    }
  });

  // Prepare SMS content
  const smsBody = `📢 Nouvelle offre publiée :\n
                   🧑‍💻 Titre: ${offreTitleExtracted}\n
                   📚 Domaine: ${offreDomaineExtracted}\n
                   📝 Type: ${offreTypeExtracted}\n
                   📍 Lieu: ${offreLocationExtracted}\n
                   📅 Début: ${offreStartDateExtracted}\n
                   📆 Fin: ${offreEndDateExtracted}`;


  // Emit WebSocket notification
  const notificationData = {
    title: offreTitleExtracted,
    domaine: offreDomaineExtracted,
    type: offreTypeExtracted,
    location: offreLocationExtracted,
    startDate: offreStartDateExtracted,
    endDate: offreEndDateExtracted
  };

  console.log("Emitting notification:", notificationData);
  io.emit("new-offre-notification", notificationData);

  // Send SMS to all valid numbers
  const sendPromises = validNumbers.map(num =>
    twilioClient.messages.create({
      body: smsBody,
      from: process.env.TWILIO_PHONE_NUMBER,
      to: num
    })
  );



  // Send SMS and emit notification
  Promise.all(sendPromises)
    .then(() => {


      return res.status(200).json({
        success: true,
        message: "📨 SMS envoyés avec succès.",
        notification: notificationData
      });
    })
    .catch(error => {
      console.error("Erreur lors de l'envoi des SMS:", error);
      return res.status(500).json({ success: false, message: "❌ Erreur interne du serveur." });
    });
});

// postuler 
app.post("/postuler", (req, res) => {
  const { utilisateur_id, offre_id } = req.body;

  if (!utilisateur_id || !offre_id) {
    return res.status(400).json({
      success: false,
      message: "utilisateur_id et offre_id sont requis."
    });
  }

  // Vérifier si l'utilisateur a déjà postulé
  const checkQuery = "SELECT * FROM candidatures WHERE utilisateur_id = ? AND offre_id = ?";
  db.query(checkQuery, [utilisateur_id, offre_id], (err, results) => {
    if (err) {
      console.error("Erreur lors de la vérification:", err);
      return res.status(500).json({ success: false, message: "Erreur serveur" });
    }

    if (results.length > 0) {
      return res.status(409).json({ success: false, message: "Vous avez déjà postulé à cette offre." });
    }

    // Si non, insérer la candidature
    const insertQuery = "INSERT INTO candidatures (utilisateur_id, offre_id) VALUES (?, ?)";
    db.query(insertQuery, [utilisateur_id, offre_id], (err, result) => {
      if (err) {
        console.error("Erreur lors de l'insertion:", err);
        return res.status(500).json({ success: false, message: "Erreur lors de la postulation." });
      }

      res.status(201).json({
        success: true,
        message: "Postulation enregistrée avec succès.",
        candidatureId: result.insertId
      });
    });
  });
});

// Favorites endpoints
app.post('/favorites', (req, res) => {
  const { user_id, offre_id } = req.body;

  if (!user_id || !offre_id) {
    return res.status(400).json({ success: false, message: "User ID and offer ID are required" });
  }

  const sql = `INSERT INTO favorite_offres (user_id, offre_id) VALUES (?, ?)`;

  db.query(sql, [user_id, offre_id], (err, result) => {
    if (err) {
      console.error("Error adding favorite:", err);
      return res.status(500).json({ success: false, message: "Error adding favorite" });
    }
    res.status(200).json({ success: true, message: "Favorite added successfully" });
  });
});

app.delete('/favorites', (req, res) => {
  const { user_id, offre_id } = req.body;

  if (!user_id || !offre_id) {
    return res.status(400).json({ success: false, message: "User ID and offer ID are required" });
  }

  const sql = `DELETE FROM favorite_offres WHERE user_id = ? AND offre_id = ?`;

  db.query(sql, [user_id, offre_id], (err, result) => {
    if (err) {
      console.error("Error removing favorite:", err);
      return res.status(500).json({ success: false, message: "Error removing favorite" });
    }
    res.status(200).json({ success: true, message: "Favorite removed successfully" });
  });
});

app.get('/favorites/:userId', (req, res) => {
  const userId = req.params.userId;

  const sql = `
    SELECT o.* 
    FROM offreemploi o
    INNER JOIN favorite_offres f ON o.id = f.offre_id
    WHERE f.user_id = ?
  `;

  db.query(sql, [userId], (err, results) => {
    if (err) {
      console.error("Error fetching favorites:", err);
      return res.status(500).json({ success: false, message: "Error fetching favorites" });
    }
    res.status(200).json(results);
  });
});

app.post('/generate-bio', async (req, res) => {
  const { bio } = req.body;

  if (!bio) {
    return res.status(400).json({ error: 'Bio input is required' });
  }

  try {
    const response = await axios.post(
      'https://openrouter.ai/api/v1/chat/completions',
      {
        model: 'mistralai/mistral-7b-instruct', // ✅ FREE MODEL
        messages: [
          {
            role: 'system',
            content: 'Vous êtes un assistant professionnel qui aide à améliorer les biographies pour les carrières.',
          },
          {
            role: 'user',
            content: `Améliore ce texte de biographie professionnelle en français : ${bio}`,
          },
        ],
      },
      {
        headers: {
          Authorization: `Bearer ${process.env.OPENAI_API_KEY}`,
          'Content-Type': 'application/json',
          'HTTP-Referer': 'http://localhost:3001', // change if deployed
          'X-Title': 'VIP Job Bio Generator',
        },
      }
    );

    let result = response.data.choices[0].message.content;

    // 🔥 Nettoyage dynamique de l'intro automatique (FR / EN)
    result = result.replace(/^[^:]*:\s*/, '');


    console.log(result);
    return res.json({ result });
  } catch (error) {
    console.error('Error generating bio:', error?.response?.data || error.message);
    res.status(500).json({ error: 'Failed to generate bio' });
  }
});


app.post('/save-bio/:userId', (req, res) => {
  const { bio } = req.body;
  const userId = req.params.userId;  // Get userId from URL parameters

  // Assuming you're using a SQL database, update the bio in the 'utilisateur' table
  const sql = `
    UPDATE utilisateur
    SET bio = ?
    WHERE id = ?
  `;

  db.query(sql, [bio, userId], (err, results) => {
    if (err) {
      console.error("Error saving bio:", err);
      return res.status(500).json({ success: false, message: "Error saving bio" });
    }

    if (results.affectedRows > 0) {
      res.status(200).json({ success: true, message: "Bio saved successfully" });
    } else {
      res.status(404).json({ success: false, message: "User not found" });
    }
  });
});
//contact


app.post('/submit-contact', async (req, res) => {
  const { name, email, subject, message } = req.body;

  let transporter = nodemailer.createTransport({
    host: 'smtp.itqanlabs.com',
    port: 587,
    secure: false,
    auth: {
      user: 'vipjob-project@itqanlabs.com',
      pass: 'JNLFWgG0A9QYNq2'
    },
    tls: {
      rejectUnauthorized: false
    }
  });

  const mailOptions = {
    from: `"${name}" <${email}>`,
    to: 'jmalminyar020@gmail.com',
    subject: subject,
    text: `Nom: ${name}\nEmail: ${email}\n\nMessage:\n${message}`
  };

  try {
    await transporter.sendMail(mailOptions);
    res.redirect('/contact?status=success');
  } catch (error) {
    console.error('Erreur email :', error);
    res.redirect('/contact?status=error');
  }
});

server.listen(3001, () => console.log("✅ Server is running on port 3001"));