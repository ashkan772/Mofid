from flask import Flask, render_template, request, redirect, url_for
from flask_sqlalchemy import SQLAlchemy

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///inventory.db'
app.config['SECRET_KEY'] = 'your_secret_key'  # Needed for forms

db = SQLAlchemy(app)

# Define database model
class Kit(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    barcode = db.Column(db.String(50), unique=True, nullable=False)

# Create database tables
with app.app_context():
    db.create_all()

# Route to view inventory
@app.route('/')
def index():
    kits = Kit.query.all()
    return render_template('index.html', kits=kits)

# Route to add a new kit
@app.route('/add', methods=['GET', 'POST'])
def add_kit():
    if request.method == 'POST':
        name = request.form['name']
        barcode = request.form['barcode']
        new_kit = Kit(name=name, barcode=barcode)
        db.session.add(new_kit)
        db.session.commit()
        return redirect(url_for('index'))
    return render_template('add_kit.html')


import os

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))

