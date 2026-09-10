"""Deliberately vulnerable Flask views - used to demonstrate secscan.

DO NOT COPY ANY OF THIS INTO REAL CODE.
"""
import hashlib
import os
import pickle
import random
import sqlite3
import subprocess

import jwt
import requests
import yaml
from flask import Flask, redirect, render_template_string, request, send_file

app = Flask(__name__)
db = sqlite3.connect("shop.db", check_same_thread=False)

STRIPE_KEY = "sk_live_4eC39HqLyjWDarjtT1zdp7dc"
DATABASE_URL = "postgres://shop_admin:hunter2SuperSecret@10.0.1.44:5432/shop"


@app.route("/search")
def search():
    term = request.args.get("q", "")
    cur = db.cursor()
    cur.execute(f"SELECT id, name, price FROM products WHERE name LIKE '%{term}%'")
    return {"results": cur.fetchall()}


@app.route("/orders/<order_id>")
def order_detail(order_id):
    cur = db.cursor()
    cur.execute("SELECT * FROM orders WHERE id = " + order_id)
    return {"order": cur.fetchone()}


@app.route("/invoice")
def invoice():
    name = request.args.get("file")
    return send_file("/var/invoices/" + name)


@app.route("/convert", methods=["POST"])
def convert():
    src = request.form["source"]
    subprocess.run(f"convert {src} /tmp/out.png", shell=True)
    return "converted"


@app.route("/greet")
def greet():
    who = request.args.get("name", "friend")
    return render_template_string("<h1>Hello " + who + "</h1>")


@app.route("/session/restore", methods=["POST"])
def restore_session():
    return {"state": str(pickle.loads(request.data))}


@app.route("/config/import", methods=["POST"])
def import_config():
    return {"config": yaml.load(request.data)}


@app.route("/fetch")
def fetch_remote():
    target = request.args.get("url")
    return requests.get(target, verify=False).text


@app.route("/login", methods=["POST"])
def login():
    pw = request.form["password"]
    digest = hashlib.md5(pw.encode()).hexdigest()
    reset_token = str(random.randint(100000, 999999))
    claims = jwt.decode(request.headers.get("X-Token", ""),
                        options={"verify_signature": False})
    cur = db.cursor()
    cur.execute("SELECT id FROM users WHERE pw = '%s'" % digest)
    return {"token": reset_token, "user": claims.get("sub")}


@app.route("/go")
def go():
    return redirect(request.args.get("next"))


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080, debug=True)
