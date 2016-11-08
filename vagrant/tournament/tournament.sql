-- Table definitions for the tournament project.
--
-- Put your SQL 'create table' statements in this file; also 'create view'
-- statements if you choose to use it.
--
-- You can write comments in this file by starting them with two dashes, like
-- these lines here.
DROP DATABASE IF EXISTS tournament;

CREATE DATABASE tournament;

\c tournament;

CREATE TABLE IF NOT EXISTS players (id SERIAL PRIMARY KEY,
                                    name TEXT);

CREATE TABLE IF NOT EXISTS matches (id SERIAL PRIMARY KEY,
                                    winner INTEGER REFERENCES players (id),
                                    loser INTEGER REFERENCES players (id));

CREATE VIEW players_standing AS SELECT players.id,
                                                players.name,
                                                COUNT(matches.winner) AS wins,
                                                ((SELECT COUNT(*) FROM matches WHERE winner = players.id) + (SELECT COUNT(*) FROM matches WHERE loser = players.id)) AS matches
                                                FROM players left join matches
                                                ON players.id = matches.winner
                                                GROUP BY players.id
                                                ORDER BY wins DESC;