from flask import Flask, render_template, request, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
import os

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///inventory.db'
app.config['SECRET_KEY'] = 'your_secret_key'  # Needed for forms

db = SQLAlchemy(app)

# Define database model
class Kit(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    barcode = db.Column(db.String(50), unique=True, nullable=False)
    quantity = db.Column(db.Integer, nullable=False, default=1)  # Added quantity field

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
        quantity = int(request.form['quantity'])  # Get quantity from form

        new_kit = Kit(name=name, barcode=barcode, quantity=quantity)
        db.session.add(new_kit)
        db.session.commit()
        return redirect(url_for('index'))

    return render_template('add_kit.html')

# Route to delete a kit
@app.route('/delete/<int:id>')
def delete_kit(id):
    kit = Kit.query.get_or_404(id)
    db.session.delete(kit)
    db.session.commit()
    return redirect(url_for('index'))

# Route to edit a kit
@app.route('/edit/<int:kit_id>', methods=['GET', 'POST'])
def edit_kit(kit_id):
    kit = Kit.query.get_or_404(kit_id)  # Fetch the kit or return 404

    if request.method == 'POST':
        kit.name = request.form['name']
        kit.barcode = request.form['barcode']
        kit.quantity = int(request.form['quantity'])  # Ensure integer conversion
        db.session.commit()
        return redirect(url_for('index'))

    return render_template('edit_kit.html', kit=kit)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))
