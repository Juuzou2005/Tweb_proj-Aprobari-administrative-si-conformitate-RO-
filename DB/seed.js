const bcrypt = require('bcryptjs');
const db = require('./database');

// Generează un fișier PDF minimal valid (în memorie, ca Buffer)
function createMinimalPdfBuffer(title, applicantName) {
  const pdfText = `%PDF-1.4
1 0 obj << /Type /Catalog /Pages 2 0 R >> endobj
2 0 obj << /Type /Pages /Kids [3 0 R] /Count 1 >> endobj
3 0 obj << /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R /Resources << /Font << /F1 5 0 R >> >> >> endobj
4 0 obj << /Length 95 >> stream
BT /F1 14 Tf 50 700 Td (${title} - Solicitant: ${applicantName}) Tj ET
endstream endobj
5 0 obj << /Type /Font /Subtype /Type1 /BaseFont /Helvetica >> endobj
xref
0 6
0000000000 65535 f 
0000000009 00000 n 
0000000058 00000 n 
0000000115 00000 n 
0000000241 00000 n 
0000000386 00000 n 
trailer << /Size 6 /Root 1 0 R >>
startxref
456
%%EOF`;
  return Buffer.from(pdfText, 'utf8');
}

const seedTransaction = db.transaction(() => {
  // Verificăm dacă există deja date
  const userCount = db.prepare('SELECT COUNT(*) AS count FROM users').get().count;
  if (userCount > 0) {
    console.log('Baza de date conține deja date. Șterge app.sqlite dacă vrei re-generare.');
    return;
  }

  const passwordHash = bcrypt.hashSync('Parola123!', 10);

  const insertUser = db.prepare(
    'INSERT INTO users (full_name, email, password_hash, role) VALUES (?, ?, ?, ?)'
  );

  // 1. Creăm utilizatorii (date 100% sintetice)
  const adminId = insertUser.run('Admin Sistem', 'admin@demo.local', passwordHash, 'admin').lastInsertRowid;

  const reviewerIds = [];
  for (let i = 1; i <= 4; i++) {
    const id = insertUser.run(
      `Evaluator Sintetic ${i}`,
      `evaluator${i}@demo.local`,
      passwordHash,
      'reviewer'
    ).lastInsertRowid;
    reviewerIds.push(id);
  }

  const applicantIds = [];
  for (let i = 1; i <= 15; i++) {
    const id = insertUser.run(
      `Solicitant Sintetic ${i}`,
      `solicitant${i}@demo.local`,
      passwordHash,
      'applicant'
    ).lastInsertRowid;
    applicantIds.push(id);
  }

  // 2. Creăm 220 de cereri sintetice pe un domeniu concret (ex. Echivalare Credite / Mobilitate)
  const statuses = ['draft', 'submitted', 'under_review', 'needs_clarification', 'approved', 'rejected'];
  const subjects = [
    'Echivalare Baze de Date',
    'Echivalare Tehnologii Web',
    'Echivalare Sisteme Distribuite',
    'Avizare Mobilitate Erasmus',
    'Recunoastere Practica de Specialitate'
  ];

  const insertRequest = db.prepare(`
    INSERT INTO requests (applicant_id, reviewer_id, title, description, status, submitted_at)
    VALUES (?, ?, ?, ?, ?, ?)
  `);

  const insertAttachment = db.prepare(`
    INSERT INTO attachments (request_id, uploaded_by, name, file_size, content)
    VALUES (?, ?, ?, ?, ?)
  `);

  const insertAudit = db.prepare(`
    INSERT INTO audit_logs (request_id, actor_id, old_status, new_status, details)
    VALUES (?, ?, ?, ?, ?)
  `);

  for (let i = 1; i <= 220; i++) {
    const applicantId = applicantIds[i % applicantIds.length];
    const status = statuses[i % statuses.length];
    const reviewerId = ['under_review', 'needs_clarification', 'approved', 'rejected'].includes(status)
      ? reviewerIds[i % reviewerIds.length]
      : null;

    const title = `${subjects[i % subjects.length]} #${i}`;
    const description = `Solicitare sintetica nr. ${i} pentru verificarea documentelor conform regulamentului.`;
    const submittedAt = status === 'draft' ? null : new Date(Date.now() - i * 3600000).toISOString();

    const requestId = insertRequest.run(
      applicantId,
      reviewerId,
      title,
      description,
      status,
      submittedAt
    ).lastInsertRowid;

    // Atașăm un PDF valid fiecărei cereri
    const pdfBuffer = createMinimalPdfBuffer(title, `Solicitant ${applicantId}`);
    insertAttachment.run(
      requestId,
      applicantId,
      `dosar_cerere_${i}.pdf`,
      pdfBuffer.length,
      pdfBuffer
    );

    // Construim istoricul de audit realist în funcție de starea cererii
    insertAudit.run(requestId, applicantId, null, 'draft', 'Cerere creata in sistem.');

    if (status !== 'draft') {
      insertAudit.run(requestId, applicantId, 'draft', 'submitted', 'Cerere depusa spre verificare.');
    }
    if (reviewerId) {
      insertAudit.run(requestId, adminId, 'submitted', 'under_review', `Repartizata evaluatorului ID ${reviewerId}.`);
    }
    if (status === 'needs_clarification') {
      insertAudit.run(requestId, reviewerId, 'under_review', 'needs_clarification', 'Va rugam sa atasati programa analitica semnata.');
    }
    if (status === 'approved') {
      insertAudit.run(requestId, reviewerId, 'under_review', 'approved', 'Documentatie completa si conforma. Aprobat.');
    }
    if (status === 'rejected') {
      insertAudit.run(requestId, reviewerId, 'under_review', 'rejected', 'Numar insuficient de credite ECTS pentru echivalare.');
    }
  }

  console.log('Seed finalizat cu succes: 20 utilizatori si 220 cereri cu PDF-uri si audit!');
});

seedTransaction();