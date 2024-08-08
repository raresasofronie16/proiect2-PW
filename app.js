const express = require('express');
const expressLayouts = require('express-ejs-layouts');
const bodyParser = require('body-parser');
const ejs = require('ejs');
const fs = require('fs');
const cookieParser = require('cookie-parser');
const session = require('express-session');
const sqlite3 = require('sqlite3').verbose();

const app = express();
const port = 6789;


//2 & 3 lab13
const failedLoginAttemptsByUsername = {};
const failedLoginAttemptsByIP = {};


const maxConsecutiveFailedAttempts = 3;
const maxTotalFailedAttempts = 5;
const shortTimeInterval =  60 * 1000; 
const longTimeInterval = 2  * 60 * 1000; 



app.set('view engine', 'ejs');
app.use(expressLayouts);
app.use(express.static('public'));
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(cookieParser());

app.use(session({
    secret: 'secret',
    resave: true,
    saveUninitialized: true
}));

// Conectare la baza de date SQLite
const db = new sqlite3.Database('cumparaturi.db', (err) => {
    if (err) {
        console.error('Eroare la conectarea la baza de date:', err);
    } else {
        console.log('Conectat la baza de date cumparaturi.db.');

        // Crearea tabelei produse dacă nu există
        db.run(`CREATE TABLE IF NOT EXISTS produse (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            denumire TEXT NOT NULL,
            pret REAL NOT NULL
        )`, (err) => {
            if (err) {
                console.error('Eroare la crearea tabelei produse:', err);
            } else {
                console.log('Tabela produse a fost creată sau deja există.');
            }
        });
    }
});

app.use((req, res, next) => {
    if (!req.session.failedRequests) {
        req.session.failedRequests = 0;
    }
    next();
});

app.use((req, res, next) => {
    if (req.session.failedRequests >= 5) {
        return res.status(403).send('Acces interzis. Ați încercat să accesați resurse inexistente de prea multe ori.');
    }
    next();
});

app.get('/', (req, res) => {
    db.all('SELECT * FROM produse', (err, rows) => {
        if (err) {
            console.error('Eroare la interogarea bazei de date:', err);
            return res.status(500).send('Eroare la interogarea bazei de date.');
        }
        const utilizator = req.session.utilizator || '';
        const tip = req.session.tip || '';
        res.render('index', { utilizator, tip, produse: rows });
    });
});

app.get('/autentificare', (req, res) => {
    const mesajEroare = req.session.mesajEroare || '';
    req.session.mesajEroare = '';
    res.render('autentificare', { mesajEroare });
});

app.post('/verificare-autentificare', (req, res) => {
    const { utilizator, parola } = req.body;
    const ip = req.ip;

    // Verificăm dacă utilizatorul a depășit numărul maxim de încercări eșuate consecutive într-un interval scurt de timp
    if (failedLoginAttemptsByUsername[utilizator] && failedLoginAttemptsByUsername[utilizator].consecutiveFailedAttempts >= maxConsecutiveFailedAttempts) {
        const lastFailedAttemptTime = failedLoginAttemptsByUsername[utilizator].lastFailedAttemptTime;
        if (Date.now() - lastFailedAttemptTime < shortTimeInterval) {
            return res.status(403).send('Acces blocat temporar. Încercați mai târziu.');
        } else {
            // Resetăm numărul de încercări eșuate consecutive
            failedLoginAttemptsByUsername[utilizator].consecutiveFailedAttempts = 0;
        }
    }

    // Verificăm dacă utilizatorul a depășit numărul maxim de încercări eșuate într-un interval mai lung de timp
    if (failedLoginAttemptsByUsername[utilizator] && failedLoginAttemptsByUsername[utilizator].totalFailedAttempts >= maxTotalFailedAttempts) {
        const lastFailedAttemptTime = failedLoginAttemptsByUsername[utilizator].lastFailedAttemptTime;
        if (Date.now() - lastFailedAttemptTime < longTimeInterval) {
            return res.status(403).send('Acces blocat temporar. Încercați mai târziu.');
        } else {
            // Resetăm numărul de încercări eșuate în intervalul mai lung de timp
            failedLoginAttemptsByUsername[utilizator].totalFailedAttempts = 0;
        }
    }

    // Verificăm dacă există deja un IP asociat cu acest utilizator și, dacă nu, îl adăugăm
    if (!failedLoginAttemptsByIP[ip]) {
        failedLoginAttemptsByIP[ip] = utilizator;
    }

    const listaUtilizatori = JSON.parse(fs.readFileSync('utilizatori.json', 'utf8'));
    const utilizatorExistent = listaUtilizatori.find(user => user.utilizator === utilizator && user.parola === parola);

    if (utilizatorExistent) {
        req.session.utilizator = utilizator;
        req.session.nume = utilizatorExistent.nume;
        req.session.prenume = utilizatorExistent.prenume;
        req.session.tip = utilizatorExistent.tip; 
         
        // Resetează numărul de încercări eșuate pentru IP și numele de utilizator
        delete failedLoginAttemptsByIP[ip];
        delete failedLoginAttemptsByUsername[utilizator];
        
        res.redirect('/');
    } else {
        // Incrementăm numărul de încercări eșuate consecutive și total pentru utilizator
        if (!failedLoginAttemptsByUsername[utilizator]) {
            failedLoginAttemptsByUsername[utilizator] = {
                consecutiveFailedAttempts: 1,
                totalFailedAttempts: 1,
                lastFailedAttemptTime: Date.now()
            };
        } else {
            failedLoginAttemptsByUsername[utilizator].consecutiveFailedAttempts++;
            failedLoginAttemptsByUsername[utilizator].totalFailedAttempts++;
        }

        // Incrementăm numărul de încercări eșuate pentru IP
        failedLoginAttemptsByIP[ip] = (failedLoginAttemptsByIP[ip] || 0) + 1;

        // Verificăm dacă utilizatorul sau IP-ul au depășit numărul maxim de încercări eșuate și blocăm temporar accesul
        if (failedLoginAttemptsByUsername[utilizator].consecutiveFailedAttempts >= maxConsecutiveFailedAttempts || 
            failedLoginAttemptsByIP[ip] >= maxConsecutiveFailedAttempts) {
            setTimeout(() => {
                delete failedLoginAttemptsByUsername[utilizator];
                delete failedLoginAttemptsByIP[ip];
            }, longTimeInterval); // Blocăm accesul temporar pentru intervalul mai lung de timp
            return res.status(403).send('Acces blocat temporar. Încercați mai târziu.');
        }
 
        req.session.mesajEroare = 'Autentificare eșuată! Utilizatorul sau parola incorectă.';
        res.redirect('/autentificare');
    }
});


app.get('/delogare', (req, res) => {
    req.session.destroy((err) => {
        if (err) {
            console.error(err);
        } else {
            res.redirect('/');
        }
    });
});

app.post('/adauga-in-cos', (req, res) => {
    const produsId = req.body.produsId;
    const utilizator = req.session.utilizator;

    if (!utilizator) {
        return res.status(403).send('Trebuie să fiți autentificat pentru a adăuga produse în coș.');
    }

    db.get('SELECT * FROM produse WHERE id = ?', [produsId], (err, produs) => {
        if (err) {
            console.error('Eroare la interogarea bazei de date:', err);
            return res.status(500).send('Eroare la interogarea bazei de date.');
        }

        if (!req.session.cos) {
            req.session.cos = [];
        }

        req.session.cos.push({ id: produsId, denumire: produs.denumire, pret: produs.pret });
        res.redirect('/vizualizare-cos');
    });
});

app.get('/vizualizare-cos', (req, res) => {
    const produseCos = req.session.cos || [];
    res.render('vizualizare-cos', { produseCos });
});

app.post('/creare-bd', (req, res) => {
    const initialData = {
        utilizatori: [],
        intrebari: []
    };

    fs.writeFile('baza_de_date.json', JSON.stringify(initialData, null, 2), (err) => {
        if (err) {
            console.error(err);
            return res.status(500).send('Eroare la crearea bazei de date.');
        }
        res.send('Baza de date a fost creată.');
    });
});

app.post('/incarcare-bd', (req, res) => {
    fs.readFile('baza_de_date.json', 'utf8', (err, data) => {
        if (err) {
            console.error(err);
            return res.status(500).send('Eroare la încărcarea bazei de date.');
        }
        const bazaDeDate = JSON.parse(data);
        res.send('Baza de date a fost încărcată cu succes.');
    });
});

app.get('/inserarebd', (req, res) => {
    db.serialize(() => {
        const produse = [
            { denumire: 'Abonament Word Premium', pret: 18.5 },
            { denumire: 'Abonament Excel Premium', pret: 20 },
            { denumire: 'Pachet Office complet', pret: 25 },
            { denumire: 'Acces la biblioteci de documente', pret: 15 },
            { denumire: 'Abonament OneDrive', pret: 50 },
            { denumire: 'Mape plastic', pret: 7.80 },
            { denumire: 'Pack for School', pret: 89 },
            { denumire: 'Mape carton', pret: 25 }
           
        ];

        const stmt = db.prepare('INSERT INTO produse (denumire, pret) VALUES (?, ?)');
        produse.forEach((produs) => {
            stmt.run(produs.denumire, produs.pret, (err) => {
                if (err) {
                    console.error('Eroare la inserarea produsului:', err);
                }
            });
        });

        stmt.finalize((err) => {
            if (err) {
                console.error('Eroare la finalizarea inserării:', err);
            }
            res.redirect('/');
        });
    });
});

function requireAdmin(req, res, next) {
    if (req.session.tip === 'ADMIN') {
        next();
    } else {
        res.status(403).send('Acces interzis. Această pagină este disponibilă doar pentru administratori.');
    }
}

app.get('/admin', requireAdmin, (req, res) => {
    res.render('admin', { mesajEroare: req.session.mesajEroare || '' });
});


/* sql inj*/
app.post('/admin', requireAdmin, (req, res) => {
    const { denumire, pret } = req.body;
    db.run('INSERT INTO produse (denumire, pret) VALUES (?, ?)', [denumire, pret], (err) => {
        if (err) {
            console.error('Eroare la adăugarea produsului:', err);
            req.session.mesajEroare = 'Eroare la adăugarea produsului.';
            return res.redirect('/admin');
        }
        res.redirect('/admin');
    });
});

app.get('/chestionar', (req, res) => {
    fs.readFile('intrebari.json', 'utf8', (err, data) => {
        if (err) {
            console.error('Eroare la citirea fișierului intrebari.json:', err);
            return res.status(500).send('Eroare la citirea întrebărilor.');
        }
        const intrebari = JSON.parse(data);
        res.render('chestionar', { intrebari });
    });
});

app.post('/rezultat-chestionar', (req, res) => {
    fs.readFile('intrebari.json', 'utf8', (err, data) => {
        if (err) {
            console.error('Eroare la citirea fișierului intrebari.json:', err);
            return res.status(500).send('Eroare la citirea întrebărilor.');
        }
        const intrebari = JSON.parse(data);
        let numarRaspunsuriCorecte = 0;

        intrebari.forEach((intrebare) => {
            const raspunsUtilizator = req.body[`intrebare_${intrebare.id}`];
            if (raspunsUtilizator !== undefined) {
                if (Array.isArray(intrebare.raspunsCorect)) {
                    // Verificăm dacă răspunsul utilizatorului este unul dintre răspunsurile corecte
                    if (intrebare.raspunsCorect.includes(parseInt(raspunsUtilizator))) {
                        numarRaspunsuriCorecte++;
                    }
                } else {
                    // Verificăm răspunsul pentru întrebările cu un singur răspuns corect
                    if (parseInt(raspunsUtilizator) === intrebare.raspunsCorect) {
                        numarRaspunsuriCorecte++;
                    }
                }
            }
        });

        const totalIntrebari = intrebari.length;
        res.render('rezultat-chestionar', {
            numarRaspunsuriCorecte,
            totalIntrebari
        });
    });
});

// Middleware pentru a gestiona resurse inexistente și contorizarea eșecurilor
app.use((req, res, next) => {
    req.session.failedRequests = (req.session.failedRequests || 0) + 1;
    if (req.session.failedRequests >= 5) {
        return res.status(403).send('Acces interzis. Ați încercat să accesați resurse inexistente de prea multe ori.');
    } else {
        res.status(404).send('Resursa solicitată nu există.');
    }
});

app.listen(port, () => console.log(`Serverul rulează la adresa http://localhost:${port}`));

