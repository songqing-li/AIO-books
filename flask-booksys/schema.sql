DROP TABLE IF EXISTS user;
DROP TABLE IF EXISTS post;
DROP TABLE IF EXISTS book;

CREATE TABLE user (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	username TEXT UNIQUE NOT NULL,
	password TEXT NOT NULL
);

CREATE TABLE post (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	author_id INTEGER NOT NULL,
	created TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
	title TEXT NOT NULL,
	body TEXT NOT NULL,
	FOREIGN KEY (author_id) REFERENCES user (id)
);

CREATE TABLE book (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	author_id INTEGER NOT NULL,
	created TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
	mingwen TEXT NOT NULL,
	str_miwen TEXT NOT NULL,
	miwen TEXT NOT NULL,
	key TEXT NOT NULL,
	enctype TEXT NOT NULL,
	FOREIGN KEY (author_id) REFERENCES user (id)
	)