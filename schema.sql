CREATE TABLE users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT UNIQUE,
  password TEXT,
  otp_secret TEXT
);

-- Solo funcionarán estos users predefinidos con TWO_FACTOR_AUTHENTICATION = False
INSERT INTO users (username, password) VALUES ('admin', 'admin123');
INSERT INTO users (username, password) VALUES ('user', 'password');