import sqlite3
from flask import Flask, render_template, request, redirect, url_for, jsonify, session, send_file
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = 'your_secret_key'

DATABASE = 'classroom_rentals.db'

# 데이터베이스 초기화 함수
def init_db():
    conn = sqlite3.connect(DATABASE)
    c = conn.cursor()

    # 예약 테이블 생성
    c.execute('''
        CREATE TABLE IF NOT EXISTS reservations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            room_number TEXT,
            user_id TEXT,
            status TEXT
        )
    ''')

    # 사용자 테이블 생성
    c.execute('''
        CREATE TABLE IF NOT EXISTS users (
            user_id TEXT PRIMARY KEY,
            password TEXT,
            name TEXT,
            student_id TEXT UNIQUE,
            phone TEXT UNIQUE
        )
    ''')

    # 관리자 테이블 생성
    c.execute('''
        CREATE TABLE IF NOT EXISTS admins (
            admin_id TEXT PRIMARY KEY,
            password TEXT
        )
    ''')

    conn.commit()
    conn.close()

# 관리자 계정 생성 함수
def init_admin():
    conn = sqlite3.connect(DATABASE)
    c = conn.cursor()
    
    admin_id = 'admin'
    admin_password = 'admin'  
    
    # 관리자 계정이 이미 존재하면 비밀번호를 업데이트하고, 없으면 생성
    c.execute("SELECT 1 FROM admins WHERE admin_id = ?", (admin_id,))
    if c.fetchone():
        # 기존 계정의 비밀번호를 업데이트
        c.execute("UPDATE admins SET password = ? WHERE admin_id = ?",
                  (generate_password_hash(admin_password), admin_id))
    else:
        # 새로운 계정 생성
        c.execute("INSERT INTO admins (admin_id, password) VALUES (?, ?)",
                  (admin_id, generate_password_hash(admin_password)))
    conn.commit()
    conn.close()



# 아이디 중복 확인 함수
def is_user_exists(user_id):
    conn = sqlite3.connect(DATABASE)
    c = conn.cursor()
    c.execute("SELECT 1 FROM users WHERE user_id = ?", (user_id,))
    result = c.fetchone()
    conn.close()
    return result is not None

# 학번 중복 확인 함수
def is_student_id_exists(student_id):
    conn = sqlite3.connect(DATABASE)
    c = conn.cursor()
    c.execute("SELECT 1 FROM users WHERE student_id = ?", (student_id,))
    result = c.fetchone()
    conn.close()
    return result is not None

# 전화번호 중복 확인 함수
def is_phone_exists(phone):
    conn = sqlite3.connect(DATABASE)
    c = conn.cursor()
    c.execute("SELECT 1 FROM users WHERE phone = ?", (phone,))
    result = c.fetchone()
    conn.close()
    return result is not None

# 학번 유효성 검사 함수
def is_valid_student_id(student_id):
    return student_id.isdigit() and len(student_id) == 8

# 전화번호 유효성 검사 함수
def is_valid_phone_number(phone):
    return phone.isdigit() and len(phone) in [10, 11]

# 사용자 정보 확인 함수
def verify_user_info(name, student_id, phone, user_id):
    conn = sqlite3.connect(DATABASE)
    c = conn.cursor()
    c.execute("SELECT 1 FROM users WHERE user_id = ? AND name = ? AND student_id = ? AND phone = ?",
              (user_id, name, student_id, phone))
    result = c.fetchone()
    conn.close()
    return result is not None

# 로그인 확인 함수
def verify_login(user_id, password):
    conn = sqlite3.connect(DATABASE)
    c = conn.cursor()

    # 사용자 로그인 검증
    c.execute("SELECT password FROM users WHERE user_id = ?", (user_id,))
    user = c.fetchone()
    is_user = False
    if user and check_password_hash(user[0], password):
        is_user = True

    # 관리자 로그인 검증
    c.execute("SELECT password FROM admins WHERE admin_id = ?", (user_id,))
    admin = c.fetchone()
    is_admin = False
    if admin and check_password_hash(admin[0], password):
        is_admin = True

    conn.close()
    return is_user, is_admin

# 강의실 예약 저장 함수
def save_reservation(room_number, user_id, status):
    conn = sqlite3.connect(DATABASE)
    c = conn.cursor()
    c.execute("INSERT INTO reservations (room_number, user_id, status) VALUES (?, ?, ?)",
              (room_number, user_id, status))
    conn.commit()
    conn.close()

################로그인

@app.route('/')
def home():
    return render_template('login.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'GET':
        return render_template('login.html')
    else:
        user_id = request.form['user_id'].strip()
        password = request.form['password'].strip()

        # 로그인 검증
        is_user, is_admin = verify_login(user_id, password)

        if is_user:
            session['user_id'] = user_id
            return redirect(url_for('user_main', user_id=user_id))
        elif is_admin:
            # 관리자 로그인 시 관리자 페이지로 리다이렉트
            return redirect(url_for('admin_main'))
        else:
            # 로그인 실패 시 로그인 페이지로 돌아감
            return render_template('login.html', error='아이디와 비밀번호를 확인해주세요.')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('home'))

################

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        user_id = request.form['user_id'].strip()
        password = request.form['password'].strip()
        confirm_password = request.form['confirm_password'].strip()
        name = request.form['name'].strip()
        student_id = request.form['student_id'].strip()
        phone = request.form['phone'].strip()

        # 학번 유효성 검사
        if not is_valid_student_id(student_id):
            return render_template('register.html', error="학번은 숫자 8자리여야 합니다.")

        # 전화번호 유효성 검사
        if not is_valid_phone_number(phone):
            return render_template('register.html', error="전화번호는 숫자 10~11자리의 숫자여야 합니다.")

        if password != confirm_password:
            return render_template('register.html', error="비밀번호가 일치하지 않습니다.")

        # 아이디 중복 확인
        if is_user_exists(user_id):
            return render_template('register.html', error="이미 중복된 아이디입니다.")

        # 학번 중복 확인
        if is_student_id_exists(student_id):
            return render_template('register.html', error="이미 등록된 학번입니다.")

        # 전화번호 중복 확인
        if is_phone_exists(phone):
            return render_template('register.html', error="이미 등록된 전화번호입니다.")

        # 비밀번호 해시화
        password_hash = generate_password_hash(password)

        # 회원 정보 저장
        conn = sqlite3.connect(DATABASE)
        c = conn.cursor()
        c.execute("INSERT INTO users (user_id, password, name, student_id, phone) VALUES (?, ?, ?, ?, ?)",
                  (user_id, password_hash, name, student_id, phone))
        conn.commit()
        conn.close()

        return render_template('success.html', name=name)

    return render_template('register.html')

@app.route('/check_user_id', methods=['POST'])
def check_user_id():
    data = request.json
    user_id = data.get('user_id')
    exists = is_user_exists(user_id)
    return jsonify({'exists': exists})

@app.route('/verify_user_info', methods=['POST'])
def verify_user_info_route():
    name = request.form['name'].strip()
    student_id = request.form['student_id'].strip()
    phone = request.form['phone'].strip()
    user_id = session.get('user_id')

    if not user_id:
        return jsonify({'is_valid': False})

    is_valid = verify_user_info(name, student_id, phone, user_id)
    return jsonify({'is_valid': is_valid})

# submit_reservation 라우트에서 user_id를 세션에서 가져오게끔
@app.route('/submit_reservation', methods=['POST'])
def submit_reservation():
    room_number = request.form['room_number']
    user_id = session.get('user_id')
    if not user_id:
        return jsonify({'success': False, 'message': '로그인이 필요합니다.'})
    status = "대여 대기"
    save_reservation(room_number, user_id, status)
    return jsonify({'success': True})

@app.route('/get_reservations', methods=['GET'])
def get_reservations():
    conn = sqlite3.connect(DATABASE)
    c = conn.cursor()
    c.execute("SELECT room_number, user_id, status FROM reservations")
    reservations = c.fetchall()
    conn.close()

    # 예약 데이터를 JSON 형태로 반환
    reservations_list = [{'room_number': r[0], 'user_id': r[1], 'status': r[2]} for r in reservations]
    return jsonify(reservations_list)

# 일반 사용자 메인 페이지
@app.route('/user_main')
def user_main():
    if 'user_id' not in session:
        return redirect(url_for('home'))
    user_id = session['user_id']
    return render_template('UI_user_Site.html', user_id=user_id)

# 관리자 메인 페이지
@app.route('/admin_main')
def admin_main():
    return render_template('UI_Admin_Site.html')

# 예약 정보 가져오기
@app.route('/get_reservation_info')
def get_reservation_info():
    room_number = request.args.get('room_number')
    conn = sqlite3.connect(DATABASE)
    c = conn.cursor()
    c.execute("SELECT user_id FROM reservations WHERE room_number = ? AND (status = '대여 대기' OR status = '대여 완료')", (room_number,))
    result = c.fetchone()

    if result:
        user_id = result[0]
        c.execute("SELECT name, student_id, phone FROM users WHERE user_id = ?", (user_id,))
        user = c.fetchone()
        conn.close()
        if user:
            name, student_id, phone = user
            return jsonify({'success': True, 'name': name, 'student_id': student_id, 'phone': phone})
        else:
            return jsonify({'success': False})
    else:
        conn.close()
        return jsonify({'success': False})

# 예약 상태 업데이트
@app.route('/update_reservation_status', methods=['POST'])
def update_reservation_status():
    room_number = request.form['room_number']
    status = request.form['status']
    conn = sqlite3.connect(DATABASE)
    c = conn.cursor()
    c.execute("UPDATE reservations SET status = ? WHERE room_number = ? AND status = '대여 대기'", (status, room_number))
    conn.commit()
    conn.close()
    return jsonify({'success': True})

# 예약 삭제
@app.route('/delete_reservation', methods=['POST'])
def delete_reservation():
    room_number = request.form['room_number']
    conn = sqlite3.connect(DATABASE)
    c = conn.cursor()
    c.execute("DELETE FROM reservations WHERE room_number = ? AND status = '대여 대기'", (room_number,))
    conn.commit()
    conn.close()
    return jsonify({'success': True})

# 대여 취소
@app.route('/cancel_rental', methods=['POST'])
def cancel_rental():
    try:
        room_number = request.form['room_number']
        conn = sqlite3.connect(DATABASE)
        c = conn.cursor()
        # '대여 완료' 상태의 예약 삭제
        c.execute("DELETE FROM reservations WHERE room_number = ? AND status = '대여 완료'", (room_number,))
        conn.commit()
        conn.close()
        return jsonify({'success': True})
    except Exception as e:
        print(f"Error in /cancel_rental: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/user_info')
def user_info():
    if 'user_id' not in session:
        return redirect(url_for('home'))
    user_id = session['user_id']
    return render_template('user_info.html', user_id=user_id)
    

@app.route('/download_application_form')
def download_application_form():
    # 로그인 여부 확인 (예시)
    if 'user_id' not in session:
        return redirect(url_for('login'))

    # hwp 파일 경로 설정
    file_path = 'application_form.hwp'

    # 파일 전송
    return send_file(file_path, as_attachment=True)



if __name__ == '__main__':
    init_db()   # 데이터베이스 초기화
    init_admin() # 관리자 계정 생성
    app.run(host='127.0.0.1', port=5000, debug=True)
