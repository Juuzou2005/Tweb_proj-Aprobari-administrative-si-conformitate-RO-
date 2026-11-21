PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS users (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    full_name     TEXT NOT NULL,
    email         TEXT NOT NULL COLLATE NOCASE UNIQUE,
    password_hash TEXT NOT NULL,
    role          TEXT NOT NULL CHECK (role IN ('applicant', 'reviewer', 'admin'))
);

CREATE TABLE IF NOT EXISTS requests (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    applicant_id  INTEGER NOT NULL,
    reviewer_id   INTEGER,
    title         TEXT NOT NULL,
    description   TEXT NOT NULL,
    status        TEXT NOT NULL DEFAULT 'draft'
                  CHECK (status IN (
                      'draft',
                      'submitted',
                      'under_review',
                      'needs_clarification',
                      'approved',
                      'rejected'
                  )),
    submitted_at  TEXT,
    updated_at    TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (applicant_id) REFERENCES users(id) ON DELETE RESTRICT,
    FOREIGN KEY (reviewer_id)  REFERENCES users(id) ON DELETE RESTRICT
);

CREATE TABLE IF NOT EXISTS attachments (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    request_id    INTEGER NOT NULL,
    uploaded_by   INTEGER NOT NULL,
    name          TEXT NOT NULL,
    file_size     INTEGER NOT NULL CHECK (file_size > 0),
    content       BLOB NOT NULL,
    FOREIGN KEY (request_id)  REFERENCES requests(id) ON DELETE RESTRICT,
    FOREIGN KEY (uploaded_by) REFERENCES users(id)    ON DELETE RESTRICT
);

CREATE TABLE IF NOT EXISTS audit_logs (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    request_id    INTEGER,
    actor_id      INTEGER NOT NULL,
    old_status    TEXT,
    new_status    TEXT,
    details       TEXT,
    occurred_at   TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (request_id) REFERENCES requests(id) ON DELETE RESTRICT,
    FOREIGN KEY (actor_id)   REFERENCES users(id)    ON DELETE RESTRICT
);

-- Triggere pentru invarianta: deciziile si jurnalul de audit nu pot fi modificate sau sterse
CREATE TRIGGER IF NOT EXISTS prevent_update_audit_logs
BEFORE UPDATE ON audit_logs
BEGIN
    SELECT RAISE(ABORT, 'Invarianta incalcata: jurnalul de audit este imutabil.');
END;

CREATE TRIGGER IF NOT EXISTS prevent_delete_audit_logs
BEFORE DELETE ON audit_logs
BEGIN
    SELECT RAISE(ABORT, 'Invarianta incalcata: jurnalul de audit nu poate fi sters.');
END;

-- Indexuri
CREATE INDEX IF NOT EXISTS idx_requests_applicant_status ON requests(applicant_id, status);
CREATE INDEX IF NOT EXISTS idx_requests_reviewer_status  ON requests(reviewer_id, status);
CREATE INDEX IF NOT EXISTS idx_requests_status           ON requests(status);
CREATE INDEX IF NOT EXISTS idx_attachments_request       ON attachments(request_id);
CREATE INDEX IF NOT EXISTS idx_audit_logs_request_time   ON audit_logs(request_id, occurred_at);