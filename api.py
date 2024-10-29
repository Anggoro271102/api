from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
import datetime
import os

app = Flask(__name__)

# Konfigurasi database MySQL atau SQLite
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://root:@localhost/magang'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Konfigurasi JWT
app.config['JWT_SECRET_KEY'] = os.getenv('JWT_SECRET_KEY', 'dafidhasgfkjahsfasfahksgfkhas')
jwt = JWTManager(app)

# Inisialisasi SQLAlchemy
db = SQLAlchemy(app)

# Model Tabel Registrasi
class Registrasi(db.Model):
    __tablename__ = 'registrasi'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)

# Model Tabel Login
class Login(db.Model):
    __tablename__ = 'login'
    userId = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), nullable=False)
    password = db.Column(db.String(120), nullable=False)
    role = db.Column(db.String(120), nullable=False)
    token = db.Column(db.String(255), nullable=True)

#Model Tabel Kamar Sewa
class RoomList(db.Model):
    __tablename__ = 'roomlist'
    id = db.Column(db.Integer, primary_key=True)
    gambar = db.Column(db.Text, nullable=False)
    no_kamar = db.Column(db.Integer, unique=True, nullable=False)
    rating = db.Column(db.Float, nullable=False)
    harga = db.Column(db.Integer, nullable=False)
    deskripsi = db.Column(db.Text, nullable=False)
    status = db.Column(db.String(50), nullable=False, default='available')
    
# Model untuk tabel booking
class Booking(db.Model):
    __tablename__ = 'booking'
    booking_id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('login.userId'), nullable=False)
    no_kamar = db.Column(db.Integer, nullable=False)
    total_harga = db.Column(db.Integer, nullable=False)

    # Relasi ke model Login (user yang melakukan booking)
    penyewa = db.relationship('Login', backref='booking')

# Route untuk registrasi
@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    hashed_password = generate_password_hash(data['password'], method='pbkdf2:sha256')

    try:
        new_user = Registrasi(username=data['username'], password=hashed_password)
        db.session.add(new_user)
        db.session.commit()

        return jsonify({"message": "success", "code": 201, "data": {}}), 201

    except Exception as e:
        return jsonify({
            "message": "Username already exists or another error",
            "code": 400,
            "data": {},
            "error": str(e)
        }), 400

# Route untuk login
@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    user = Registrasi.query.filter_by(username=data['username']).first()
    if not user or not check_password_hash(user.password, data['password']):
        return jsonify({"message": "Invalid credentials", "code": 401, "data": {}}), 401

    expires = datetime.timedelta(minutes=30)
    access_token = create_access_token(identity=user.username, expires_delta=expires)
    
    login_entry = Login(userId=user.id, username=user.username, password=user.password, role = "user", token=access_token)
    db.session.add(login_entry)
    db.session.commit()

    return jsonify({"message": "success", "code": 200, "data": {"role": "user" ,"access_token": access_token}}), 200

# Route untuk list kamar
@app.route('/list_room', methods=['GET'])
@jwt_required()
def get_kamar_sewa():
    # Ambil semua data dari tabel kamar_sewa yang statusnya 'available'
    kamar_list = RoomList.query.filter_by(status='available').all()

    # Jika tidak ada data
    if not kamar_list:
        return jsonify({"message": "No available rooms", "code": 404}), 404

    # Format data menjadi JSON
    kamar_sewa_list = []
    for kamar in kamar_list:
        kamar_sewa_list.append({
            "id": kamar.id,
            "gambar": kamar.gambar,
            "no_kamar": kamar.no_kamar,
            "rating": kamar.rating,
            "harga": kamar.harga,
            "deskripsi": kamar.deskripsi,
            "status": kamar.status
        })

    return jsonify({
        "message": "success",
        "code": 200,
        "data": kamar_sewa_list
    }), 200

# Route untuk list kamar untuk adminn
@app.route('/list/all_room', methods=['GET'])
@jwt_required()
def get_kamar_sewa_for_admin():
    kamar_list = RoomList.query.all()

    # Jika tidak ada data
    if not kamar_list:
        return jsonify({"message": "No available rooms", "code": 404}), 404

    # Format data menjadi JSON
    kamar_sewa_list = []
    for kamar in kamar_list:
        kamar_sewa_list.append({
            "id": kamar.id,
            "gambar": kamar.gambar,
            "no_kamar": kamar.no_kamar,
            "rating": kamar.rating,
            "harga": kamar.harga,
            "deskripsi": kamar.deskripsi,
            "status": kamar.status
        })

    return jsonify({
        "message": "success",
        "code": 200,
        "data": kamar_sewa_list
    }), 200
    
# api untuk menambah kamar
@app.route('/add_room', methods=['POST'])
@jwt_required()  # Hanya pengguna yang sudah login yang bisa menambah kamar
def add_kamar():
    data = request.get_json()

    # Validasi input data
    if 'gambar' not in data or 'no_kamar' not in data or 'rating' not in data or 'harga' not in data or 'deskripsi' not in data or 'status' not in data:
        return jsonify({"message": "Incomplete data", "code": 400}), 400

    try:
        # Tambah kamar baru ke database
        new_kamar = RoomList(
            gambar=data['gambar'],
            no_kamar=data['no_kamar'],
            rating=data['rating'],
            harga=data['harga'],
            deskripsi=data['deskripsi'],
            status=data['status']
        )
        db.session.add(new_kamar)
        db.session.commit()

        return jsonify({"message": "Kamar added successfully", "code": 201}), 201

    except Exception as e:
        return jsonify({"message": "Error adding room", "code": 400, "error": str(e)}), 400

# API untuk mengubah status kamar
@app.route('/update_room', methods=['PUT'])
@jwt_required()  # Hanya pengguna yang sudah login yang bisa mengubah status kamar
def update_kamar_status():
    data = request.get_json()

    # Validasi input data
    if 'no_kamar' not in data or 'status' not in data:
        return jsonify({"message": "Incomplete data", "code": 400}), 400

    # Cari kamar berdasarkan nomor kamar
    kamar = RoomList.query.filter_by(no_kamar=data['no_kamar']).first()

    if not kamar:
        return jsonify({"message": "Kamar not found", "code": 404}), 404

    # Perbarui status kamar
    kamar.status = data['status']
    db.session.commit()

    return jsonify({"message": "Kamar status updated successfully", "code": 200}), 200

# API Login untuk admin
@app.route('/admin/login', methods=['POST'])
def admin_login():
    data = request.get_json()

    # Validasi input
    if not data or 'username' not in data or 'password' not in data:
        return jsonify({"message": "Username and password are required", "code": 400}), 400

    # Cari username di tabel login
    admin = Login.query.filter_by(username=data['username']).first()

    # Jika username tidak ditemukan atau password salah
    if not admin or not check_password_hash(admin.password, data['password']):
        return jsonify({"message": "Invalid credentials", "code": 401}), 401

    # Pastikan pengguna memiliki role 'admin'
    if admin.role != 'admin':
        return jsonify({"message": "Unauthorized: Admin access only", "code": 403}), 403

    # Jika login berhasil, buat token JWT
    access_token = create_access_token(identity=admin.username)

    # Simpan token ke database (opsional, jika kamu ingin menyimpan token di tabel)
    admin.token = access_token
    db.session.commit()

    return jsonify({
        "message": "Login successful",
        "code": 200,
        "access_token": access_token,
        "role" : "admin"
    }), 200

# API untuk menambah booking
@app.route('/booking', methods=['POST'])
@jwt_required()  # Hanya pengguna dengan token yang valid yang bisa menambah booking
def add_booking():
    data = request.get_json()

    # Validasi input data
    if 'user_id' not in data or 'no_kamar' not in data or 'total_harga' not in data:
        return jsonify({"message": "Incomplete data", "code": 400}), 400

    try:
        # Tambah booking baru ke database
        new_booking = Booking(
            user_id=data['user_id'],
            no_kamar=data['no_kamar'],
            total_harga=data['total_harga']
        )
        db.session.add(new_booking)
        db.session.commit()

        return jsonify({"message": "Booking added successfully", "code": 201}), 201

    except Exception as e:
        return jsonify({"message": "Error adding booking", "code": 400, "error": str(e)}), 400


# API untuk mendapatkan list booking
@app.route('/booking/list', methods=['GET'])
@jwt_required()  # Hanya pengguna dengan token yang valid yang bisa melihat booking list
def get_booking_list():
    booking_list = Booking.query.all()

    if not booking_list:
        return jsonify({"message": "No bookings available", "code": 404}), 404

    # Format data menjadi JSON
    bookings = []
    for booking in booking_list:
        bookings.append({
            "booking_id": booking.booking_id,
            "user_id": booking.user_id,
            "username": booking.penyewa.username,  # Dapatkan nama penyewa dari relasi
            "no_kamar": booking.no_kamar,
            "total_harga": booking.total_harga
        })

    return jsonify({
        "message": "success",
        "code": 200,
        "data": bookings
    }), 200

# Jalankan aplikasi
if __name__ == '__main__':
    with app.app_context():
        db.create_all()  # Membuat tabel jika belum ada
    app.run(debug=True)
