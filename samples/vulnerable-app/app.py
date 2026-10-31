"""Deliberately vulnerable demo application for testing CodeGuardian AI.
DO NOT deploy this code. Every issue here is intentional."""
import hashlib
import os
import pickle
import random
import sqlite3
import subprocess

import requests
import yaml
from flask import Flask, render_template_string, request

app = Flask(__name__)

DB_PASSWORD = "SuperSecret123!"
API_KEY = "sk_live_51HxDemoKeyForTestingOnly0000000"
AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"


def get_db():
    return sqlite3.connect("users.db")


@app.route("/user")
def get_user():
    user_id = request.args.get("id")
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute(f"SELECT * FROM users WHERE id = '{user_id}'")
    return str(cursor.fetchone())


@app.route("/search")
def search():
    term = request.args.get("q", "")
    query = "SELECT * FROM products WHERE name LIKE '%" + term + "%'"
    conn = get_db()
    return str(conn.execute(query).fetchall())


@app.route("/ping")
def ping():
    host = request.args.get("host")
    output = subprocess.check_output("ping -c 1 " + host, shell=True)
    os.system("echo pinged " + host)
    return output


@app.route("/calc")
def calc():
    expr = request.args.get("expr")
    return str(eval(expr))


@app.route("/hello")
def hello():
    name = request.args.get("name", "guest")
    return render_template_string("<h1>Hello " + name + "</h1>")


@app.route("/load", methods=["POST"])
def load_session():
    data = request.get_data()
    session = pickle.loads(data)
    return str(session)


@app.route("/config", methods=["POST"])
def load_config():
    cfg = yaml.load(request.data)
    return str(cfg)


@app.route("/file")
def read_file():
    filename = request.args.get("name")
    with open(os.path.join("uploads", filename)) as fh:
        return fh.read()


@app.route("/fetch")
def fetch_url():
    url = request.args.get("url")
    return requests.get(url, verify=False).text


def hash_password(password):
    return hashlib.md5(password.encode()).hexdigest()


def generate_reset_token():
    reset_token = str(random.randint(100000, 999999))
    return reset_token


def check_admin(user):
    assert user.is_admin, "admin only"
    return True


if __name__ == "__main__":
    app.run(host="0.0.0.0", debug=True)
