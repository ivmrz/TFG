CREATE TABLE users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT UNIQUE,
  password TEXT,
  otp_secret TEXT
);

-- Solo funcionarán estos users predefinidos con PASSWORD_HASHING y TWO_FACTOR_AUTHENTICATION = False
INSERT INTO users (username, password, otp_secret) VALUES ('admin', 'admin123', NULL);
INSERT INTO users (username, password, otp_secret) VALUES ('user', 'password', NULL);