import os
import pandas as pd
from flask import (Flask, render_template, request, redirect, url_for, flash,
                   send_file, jsonify)
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import (LoginManager, UserMixin, login_user, logout_user,
                         login_required, current_user)
from datetime import datetime, time, timedelta
from sqlalchemy import or_
import io
from collections import defaultdict
import json

# --- Inisialisasi & Konfigurasi ---
app = Flask(__name__)
app.config['SECRET_KEY'] = 'kunci-rahasia-untuk-proyek-uas-bookingapp'
db_path = os.path.join(os.path.abspath(os.path.dirname(__file__)), 'database.db')
app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{db_path}'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.login_message = 'Silakan login untuk mengakses halaman ini.'
login_manager.login_message_category = 'info'

# --- Data Statis ---
data_gedung = {
    "A": {
        "3": ["Lab Komputer Mesin 1", "Lab Komputer Mesin 2", "A3A"],
        "4": ["Lab Komputer Hardware", "Lab Komputer Software", "A4A"],
        "5": ["Lab Komputer DKV 1", "Lab Komputer DKV 2", "A5A"]
    },
    "B": {
        "1": ["Lab Teknik Sipil", "Lab Teknik Elektro"],
        "2": [f"B2{h}" for h in "ABCDEFGH"], "3": [f"B3{h}" for h in "ABCDEFGH"],
        "4": [f"B4{h}" for h in "ABCDEFGH"], "5": [f"B5{h}" for h in "ABCDEFGH"]
    }
}
HARI_LIST = ['Senin', 'Selasa', 'Rabu', 'Kamis', 'Jumat', 'Sabtu', 'Minggu']
ALLOWED_LANTAI3_ROOMS = ['B3A', 'B3B', 'B3C', 'B3D', 'B3E', 'B3F', 'B3G', 'B3H']
EXCLUDED_LAB_ROOMS_FOR_GENERATION = {
    "Lab Komputer Hardware", "Lab Komputer Software", "Lab Komputer Mesin 1",
    "Lab Komputer Mesin 2", "Lab Komputer DKV 1", "Lab Komputer DKV 2",
    "Lab Teknik Sipil", "Lab Teknik Elektro"
}

# --- Model Database ---
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)
    role = db.Column(db.String(80), nullable=False)

class Jadwal(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    nama_dosen = db.Column(db.String(120), nullable=False)
    mata_kuliah = db.Column(db.String(120), nullable=False)
    kelas = db.Column(db.String(80), nullable=False)
    hari = db.Column(db.String(20), nullable=False)
    jam_mulai = db.Column(db.String(5), nullable=False)
    jam_selesai = db.Column(db.String(5), nullable=False)
    gedung = db.Column(db.String(20))
    lantai = db.Column(db.String(20))
    ruangan = db.Column(db.String(80))
    tipe_kelas = db.Column(db.String(20), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    sks = db.Column(db.Integer, nullable=False)

# --- Fungsi Bantuan ---
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

def parse_time(t_str):
    for fmt in ("%H:%M", "%H.%M", "%H:%M:%S"):
        try:
            return datetime.strptime(str(t_str), fmt).time()
        except (ValueError, TypeError):
            continue
    return None

def is_bentrok(hari, mulai_baru, selesai_baru, ruangan, kelas, nama_dosen, tipe_kelas, jadwal_id_to_ignore=None):
    mulai_baru_time, selesai_baru_time = parse_time(mulai_baru), parse_time(selesai_baru)
    if not (mulai_baru_time and selesai_baru_time): return False

    query = Jadwal.query.filter(
        Jadwal.hari == hari,
        Jadwal.id != jadwal_id_to_ignore,
        db.func.time(Jadwal.jam_selesai) > mulai_baru_time,
        db.func.time(Jadwal.jam_mulai) < selesai_baru_time
    )
    
    conditions = []
    if tipe_kelas == 'Offline':
        conditions.append(Jadwal.ruangan == ruangan)
    conditions.append(Jadwal.kelas == kelas)
    conditions.append(Jadwal.nama_dosen == nama_dosen)
    
    query = query.filter(or_(*conditions))
    return db.session.query(query.exists()).scalar()

# --- Rute Autentikasi ---
@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated: return redirect(url_for('landing_page'))
    if request.method == 'POST':
        user = User.query.filter_by(username=request.form.get('username')).first()
        if user and bcrypt.check_password_hash(user.password, request.form.get('password')):
            login_user(user)
            return redirect(url_for('landing_page'))
        flash('Login gagal. Periksa kembali username dan password Anda.', 'danger')
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated: return redirect(url_for('landing_page'))
    if request.method == 'POST':
        username = request.form.get('username')
        if User.query.filter_by(username=username).first():
            flash('Username sudah digunakan.', 'warning')
            return redirect(url_for('register'))
        
        hashed_password = bcrypt.generate_password_hash(request.form.get('password')).decode('utf-8')
        new_user = User(username=username, password=hashed_password, role='dosen') # Default role Dosen
        db.session.add(new_user)
        db.session.commit()
        flash('Akun dosen Anda berhasil dibuat! Silakan login.', 'success')
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

# --- Rute Utama Aplikasi ---
@app.route('/')
@login_required
def landing_page():
    return render_template('landing_page.html')

@app.route('/jadwal')
@login_required
def halaman_jadwal():
    filter_by = request.args.get('filter_by', 'Hari')
    filter_value = request.args.get('filter_value', '').strip()
    query = Jadwal.query
    if filter_value:
        search = f"%{filter_value}%"
        if filter_by == 'Hari': query = query.filter(Jadwal.hari.ilike(search))
        elif filter_by == 'Ruangan': query = query.filter(Jadwal.ruangan.ilike(search))
        elif filter_by == 'Kelas': query = query.filter(Jadwal.kelas.ilike(search))
        elif filter_by == 'Dosen': query = query.filter(Jadwal.nama_dosen.ilike(search))
    
    jadwal_list = query.order_by(Jadwal.id.desc()).all()
    return render_template('view_jadwal.html', jadwal_list=jadwal_list,
                           filter_by=filter_by, filter_value=filter_value)

@app.route('/booking', methods=['GET', 'POST'])
@login_required
def halaman_booking():
    if current_user.role == 'mahasiswa':
        flash('Anda tidak memiliki hak akses untuk halaman ini.', 'warning')
        return redirect(url_for('landing_page'))

    if request.method == 'POST':
        form = request.form
        dosen = current_user.username if current_user.role == 'dosen' else form.get('dosen')
        tipe_kelas = form.get('tipe_kelas')
        ruangan = form.get('ruangan') if tipe_kelas == 'Offline' else 'Online'
        
        if is_bentrok(form.get('hari'), form.get('jam_mulai'), form.get('jam_selesai'), 
                        ruangan, form.get('kelas'), dosen, tipe_kelas):
            flash(f"Jadwal Bentrok! Ruangan, kelas, atau dosen sudah digunakan.", "danger")
            return render_template('booking_form.html', form_data=form)

        new_jadwal = Jadwal(
            nama_dosen=dosen, mata_kuliah=form.get('matkul'), kelas=form.get('kelas'),
            hari=form.get('hari'), jam_mulai=form.get('jam_mulai'), jam_selesai=form.get('jam_selesai'),
            gedung=form.get('gedung') if tipe_kelas == 'Offline' else 'Online',
            lantai=form.get('lantai') if tipe_kelas == 'Offline' else 'N/A',
            ruangan=ruangan, tipe_kelas=tipe_kelas, sks=0, user_id=current_user.id
        )
        db.session.add(new_jadwal)
        db.session.commit()
        flash('Booking berhasil disimpan!', 'success')
        return redirect(url_for('halaman_jadwal'))

    form_data = dict(request.args)
    if current_user.role == 'dosen':
        form_data['dosen'] = current_user.username
    return render_template('booking_form.html', form_data=form_data)


@app.route('/ruangan_tersedia')
@login_required
def halaman_ruangan_tersedia():
    if current_user.role == 'mahasiswa':
        flash('Anda tidak memiliki hak akses untuk halaman ini.', 'warning'); return redirect(url_for('landing_page'))
    selected_day = request.args.get('hari')
    room_availability_blocks = {}

    if selected_day:
        all_rooms_unfiltered = []
        for gedung, lantai_data in data_gedung.items():
            for lantai, rooms in lantai_data.items():
                if gedung == 'B' and lantai == '3':
                    all_rooms_unfiltered.extend([r for r in rooms if r in ALLOWED_LANTAI3_ROOMS])
                else:
                    all_rooms_unfiltered.extend(rooms)
        all_rooms = sorted(list(set(all_rooms_unfiltered)))

        existing_schedules = Jadwal.query.filter_by(hari=selected_day, tipe_kelas='Offline').all()
        time_slots = [ (datetime.combine(datetime.min, time(7,0)) + timedelta(minutes=15*i)).time() for i in range(60) ]

        booked_slots = defaultdict(set)
        for sched in existing_schedules:
            start_t, end_t = parse_time(sched.jam_mulai), parse_time(sched.jam_selesai)
            if not start_t or not end_t: continue
            
            current_slot = datetime.combine(datetime.min, start_t)
            end_slot = datetime.combine(datetime.min, end_t)
            while current_slot < end_slot:
                booked_slots[current_slot.time()].add(sched.ruangan)
                current_slot += timedelta(minutes=15)

        istirahat_mulai, istirahat_selesai = time(12, 0), time(13, 0)
        
        for room in all_rooms:
            blocks = []
            start_block_time = time_slots[0]
            current_status = ""

            for i, slot in enumerate(time_slots):
                status = "Terpakai"
                if istirahat_mulai <= slot < istirahat_selesai:
                    status = "Istirahat"
                elif room not in booked_slots.get(slot, set()):
                    status = "Tersedia"
                
                if i == 0:
                    current_status = status
                
                if status != current_status:
                    blocks.append({
                        'start': start_block_time.strftime("%H:%M"),
                        'end': slot.strftime("%H:%M"),
                        'status': current_status
                    })
                    start_block_time = slot
                    current_status = status

            blocks.append({
                'start': start_block_time.strftime("%H:%M"),
                'end': (datetime.combine(datetime.min, time_slots[-1]) + timedelta(minutes=15)).strftime("%H:%M"),
                'status': current_status
            })
            room_availability_blocks[room] = blocks

    return render_template('ruangan_tersedia.html', days=HARI_LIST, selected_day=selected_day, room_availability_blocks=room_availability_blocks)


@app.route('/generate_jadwal', methods=['GET', 'POST'])
@login_required
def halaman_generate():
    if current_user.role != 'admin':
        flash('Anda tidak memiliki hak akses.', 'danger')
        return redirect(url_for('landing_page'))
    if request.method == 'POST':
        # Logika untuk generate jadwal dari file asli bisa ditambahkan di sini
        flash("Fitur generate sedang dalam pengembangan.", "info")
        return redirect(url_for('halaman_generate'))
        
    return render_template('generate_jadwal.html')

# --- Rute Aksi & Download ---
@app.route('/delete_jadwal/<int:jadwal_id>', methods=['POST'])
@login_required
def delete_jadwal(jadwal_id):
    if current_user.role != 'admin':
        flash('Aksi tidak diizinkan.', 'danger')
        return redirect(url_for('halaman_jadwal'))
    jadwal = Jadwal.query.get_or_404(jadwal_id)
    db.session.delete(jadwal)
    db.session.commit()
    flash('Jadwal berhasil dihapus.', 'success')
    return redirect(url_for('halaman_jadwal'))

@app.route('/delete_all_schedules', methods=['POST'])
@login_required
def delete_all_schedules():
    if current_user.role != 'admin':
        flash('Aksi tidak diizinkan.', 'danger');
        return redirect(url_for('halaman_jadwal'))
    try:
        num_deleted = db.session.query(Jadwal).delete()
        db.session.commit()
        flash(f'{num_deleted} jadwal berhasil dihapus.', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Terjadi error saat menghapus semua jadwal: {e}', 'danger')
    return redirect(url_for('halaman_jadwal'))

@app.route('/download_template')
@login_required
def download_template():
    output = io.BytesIO()
    df_template = pd.DataFrame(columns=['KODE', 'DOSEN PENGAJAR', 'MATA KULIAH', 'SMT', 'SKS', 'KELAS', 'DOSEN_HARI_KAMPUS', 'DOSEN_JAM_KAMPUS', 'TIPE_KELAS'])
    with pd.ExcelWriter(output, engine='openpyxl') as writer: df_template.to_excel(writer, index=False, sheet_name='Sheet1')
    output.seek(0)
    return send_file(output, mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet', download_name='template_generate_jadwal.xlsx', as_attachment=True)


@app.route('/download_excel')
@login_required
def download_excel():
    query = Jadwal.query.order_by(Jadwal.hari, Jadwal.jam_mulai).all()
    df = pd.DataFrame([(d.id, d.nama_dosen, d.mata_kuliah, d.sks, d.kelas, d.hari, d.jam_mulai, d.jam_selesai, d.gedung, d.lantai, d.ruangan, d.tipe_kelas) for d in query],
                      columns=["ID", "Dosen", "Matkul", "SKS", "Kelas", "Hari", "Mulai", "Selesai", "Gedung", "Lantai", "Ruangan", "Tipe"])
    output = io.BytesIO()
    with pd.ExcelWriter(output, engine='openpyxl') as writer:
        df.to_excel(writer, index=False, sheet_name='Jadwal')
    output.seek(0)
    return send_file(output, download_name='jadwal_lengkap.xlsx', as_attachment=True)

# --- Fungsi Inisialisasi ---
@app.context_processor
def inject_data():
    return dict(data_gedung=data_gedung)

def init_database():
    with app.app_context():
        db.create_all()
        if not User.query.filter_by(username='admin').first():
            hashed_password = bcrypt.generate_password_hash('admin').decode('utf-8')
            admin_user = User(username='admin', password=hashed_password, role='admin')
            db.session.add(admin_user)
            db.session.commit()

if __name__ == '__main__':
    if not os.path.exists(db_path):
        init_database()
    app.run(debug=True)