spring-security-test
=========

### User Schema

```sql
CREATE DATABASE `spring-security-test`;
USE `spring-security-test`;

CREATE TABLE `users` (
  `username` VARCHAR(50) NOT NULL COLLATE 'utf8_unicode_ci',
  `password` VARCHAR(50) NOT NULL COLLATE 'utf8_unicode_ci',
  `enabled` TINYINT(1) NOT NULL,
  PRIMARY KEY (`username`),
  UNIQUE INDEX `username` (`username`)
)
COLLATE='utf8_unicode_ci'

CREATE TABLE `authorities` (
  `username` VARCHAR(50) NOT NULL COLLATE 'utf8_unicode_ci',
  `authority` VARCHAR(50) NOT NULL COLLATE 'utf8_unicode_ci',
  INDEX `fk_authorities_users` (`username`),
  CONSTRAINT `fk_authorities_users` FOREIGN KEY (`username`) REFERENCES `users` (`username`)
)
COLLATE='utf8_unicode_ci'

INSERT INTO `authorities` (`username`, `authority`) VALUES ('user1', 'ROLE_USER');

INSERT INTO `users` (`id`, `username`, `password`, `enabled`) VALUES (1, 'user1', 'pass', 1);
```