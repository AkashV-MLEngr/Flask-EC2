from datetime import datetime
import os
import bcrypt as bcrypt
import mysql.connector
import pytz as pytz
import requests as requests
from flask import Flask, render_template, flash, redirect, request, session, url_for
from geopy.geocoders import Nominatim

secret_key = os.urandom(24)
painmgmt = Flask(__name__)
geolocator = Nominatim(user_agent="my_geocoder")
painmgmt.secret_key = secret_key
#
# pain = mysql.connector.connect(
#     user='Medisim',
#     password='4wWEvP6XVezhLmpqeavl',
#     database='PAIN_MANAGEMENT',
#     host='medisim-testdb.cbmmrisq24o6.us-west-2.rds.amazonaws.com',
#     # host='flaskdb.cnica2ouqc9r.eu-north-1.rds.amazonaws.com',
#     port=3306,
#     auth_plugin='mysql_native_password',
#     autocommit=True,  # Ensure autocommit is set to True
# )
# cursor = pain.cursor()
pain = mysql.connector.connect(
    user='Medisim',
    password='K60KSH2DOXQn8BGnM3SA',
    database='PAIN_MANAGEMENT',
    host='flaskdb.cnica2ouqc9r.eu-north-1.rds.amazonaws.com',
    port=3306,
    auth_plugin='mysql_native_password',
    autocommit=True,  # Ensure autocommit is set to True
)
cursor = pain.cursor()


def user_time():
    current_time = datetime.now()
    formatted_time = current_time.strftime('%Y-%m-%d %H:%M:%S')
    return formatted_time


# Before deployment have to uncomment this
# def user_time():
#     ist = pytz.timezone('Asia/Kolkata')  # IST time zone
#     utc_time = datetime.utcnow()
#     ist_time = utc_time.astimezone(ist)
#     formatted_time = ist_time.strftime('%Y-%m-%d %H:%M:%S')
#     return formatted_time


def get_user_ip():
    if 'X-Forwarded-For' in request.headers:
        # Use the first IP in the X-Forwarded-For header
        user_ip = request.headers['X-Forwarded-For'].split(',')[0].strip()
    else:
        # Use the default remote_addr
        user_ip = request.remote_addr
    return user_ip


def get_user_location(ip):
    try:
        url = f"https://ipinfo.io/{ip}/json"
        response = requests.get(url)
        data = response.json()
        # Extract relevant location information
        city = data.get('city')
        country = data.get('country')
        return f"{city}, {country}"
    except Exception as e:
        print("Error fetching location:", e)
        return None


def hash_password(password):
    # Generate a salt and hash the password
    salt = bcrypt.gensalt()
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), salt)
    return hashed_password


# Function to check if the provided password matches the stored hash
def check_password(stored_hash, password):
    return bcrypt.checkpw(password.encode('utf-8'), stored_hash.encode('utf-8'))


def dev_pwd_extract(dev_pwd, hashed_password):
    # Check if the password matches
    if bcrypt.checkpw(dev_pwd.encode('utf-8'),hashed_password.encode('utf-8')):
        return hashed_password
    else:
        return None


@painmgmt.route('/')
def login():
    return render_template('login.html')


@painmgmt.route('/logout')
def logout():
    return render_template('login.html')


@painmgmt.route('/login_success', methods=['POST'])
def success():
    global username, password
    if request.method == 'POST':
        session['username'] = request.form['username']
        username = session.get('username')
        password = request.form['password']

    usersql = "SELECT user_id, password, lock_status, number_of_failure_attempts, role, institution_name FROM " \
              "user_details WHERE binary user_id = %s and lock_status=0"
    cursor.execute(usersql, (username,))
    user = cursor.fetchone()
    if user:
        stored_hashed_password = user[1]
        current_attempts = int(user[3])
        role = user[4]
        session['ins'] = user[5]
        ins = session.get('ins')
        print(ins)
        if role == 'Super Admin':
            if check_password(stored_hashed_password, password):
                time = user_time()
                ip = get_user_ip()
                update_sql = "UPDATE user_details SET last_login_details = %s, logged_in_ip = %s WHERE " \
                             "user_id = %s "
                cursor.execute(update_sql, (time, ip, username))
                pain.commit()
                device_count_sql = "SELECT count(*) FROM device_details WHERE device_status = 0"
                cursor.execute(device_count_sql)
                devices_count = cursor.fetchall()
                devices = [dv[0] for dv in devices_count]
                return render_template('super_admin_dashboard.html', devices=devices)
            else:
                new_attempts = current_attempts + 1
                update_sql = "UPDATE user_details SET number_of_failure_attempts = %s WHERE user_id = %s "
                cursor.execute(update_sql, (new_attempts, username))
                pain.commit()
                if new_attempts > 3:
                    update_sql = "UPDATE user_details SET lock_status = 2 WHERE user_id = %s "
                    cursor.execute(update_sql, (username,))
                    pain.commit()
                flash(f"Incorrect Password....! Limit Exceeds {current_attempts} of 3")
                return redirect('/')
        else:
            if check_password(stored_hashed_password, password):
                time = user_time()
                ip = get_user_ip()
                print("Else Block" + " " + str(ins))
                update_sql = "UPDATE user_details SET last_login_details = %s, logged_in_ip = %s WHERE " \
                             "user_id = %s "
                cursor.execute(update_sql, (time, ip, username))
                pain.commit()
                device_count_sql = "SELECT count(*) FROM device_details WHERE device_allocated_for = %s AND " \
                                   "device_status = 0 "
                cursor.execute(device_count_sql, (ins,))
                devices_count = cursor.fetchall()
                devices = [dv[0] for dv in devices_count]
                return render_template('admin_dashboard.html', devices=devices)
            else:
                new_attempts = current_attempts + 1
                update_sql = "UPDATE user_details SET number_of_failure_attempts = %s WHERE user_id = %s "
                cursor.execute(update_sql, (new_attempts, username))
                pain.commit()
                if new_attempts > 3:
                    update_sql = "UPDATE user_details SET lock_status = 2 WHERE user_id = %s "
                    cursor.execute(update_sql, (username,))
                    pain.commit()
                flash(f"Incorrect Password....! Limit Exceeds {current_attempts} of 3")
                return redirect('/')

    else:
        flash("Invalid User/ Account Locked....!")
        return redirect('/')


@painmgmt.route('/super_admin/dashboard')
def sa_dashboard():
    device_count_sql = "SELECT count(*) FROM device_details WHERE device_status = 0"
    cursor.execute(device_count_sql)
    devices = cursor.fetchall()
    device_count = [dv[0] for dv in devices]
    return render_template("super_admin_dashboard.html", devices=device_count)


@painmgmt.route('/admin/dashboard')
def a_dashboard():
    ins = session.get('ins')
    device_count_sql = "SELECT count(*) FROM device_details WHERE device_allocated_for = %s AND device_status = 0"
    cursor.execute(device_count_sql, (ins,))
    devices = cursor.fetchall()
    device_count = [dv[0] for dv in devices]
    return render_template("admin_dashboard.html", devices=device_count)


@painmgmt.route('/super_admin/institution')
def ins():
    ins_cltd_sql = "SELECT * FROM institution_details"
    cursor.execute(ins_cltd_sql)
    ins = cursor.fetchall()
    return render_template("institution.html", ins=ins)


@painmgmt.route('/super_admin/ins_creation', methods=['POST'])
def ins_creation():
    global ins_id
    cursor = pain.cursor()
    cursor.execute("SELECT prefix, start_id, current_id FROM id_generation where category_name='institute' ")
    result = cursor.fetchone()
    if result:
        prefix, start_number, current_id = result
        ins_id = f"{prefix}{current_id}"
        new_current_id = int(current_id) + 1
        new_current_id_str = f"{new_current_id:03d}"
        cursor.execute("UPDATE id_generation SET current_id = %s where category_name='institute' ",
                       (new_current_id_str,))

    if request.method == 'POST':
        ins_name = request.form['ins_name']
        cntct_number = request.form['cntct_number']
        cntct_email = request.form['cntct_email']
        time = user_time()
        ip = get_user_ip()
        username = session.get('username')
        ins_add_sql = """INSERT INTO institution_details(institute_id, institute_name, contact_number, contact_email, 
        lock_status, created_by, timestamp, ip_address) VALUES(%s, %s, %s, %s, %s, %s, %s, %s) """
        ins_add_val = (
            ins_id, ins_name, cntct_number, cntct_email, 0, username, time,
            ip)
        cursor.execute(ins_add_sql, ins_add_val)
        pain.commit()
        flash("Institution Created Successfully..!")
    return redirect("/super_admin/institution")


@painmgmt.route('/super_admin/devices')
def devices():
    u_name = session.get('username')

    device_clct_sql = "SELECT * FROM device_details"
    cursor.execute(device_clct_sql)
    devices = cursor.fetchall()

    ins_cltd_sql = "SELECT * FROM institution_details WHERE lock_status=0"
    cursor.execute(ins_cltd_sql)
    ins = cursor.fetchall()

    decrypted_passwords = []
    for device in devices:
        hashed_password = device[5]  # Assuming the hashed password is at index 5
        decrypted_password = dev_pwd_extract(device[5], hashed_password)
        decrypted_passwords.append(decrypted_password)

    print(decrypted_passwords)

    return render_template("device_controller.html", devices=devices, u_name=u_name, ins=ins)




@painmgmt.route('/super_admin/device_controller', methods=['POST'])
def device_controller():
    global dev_id
    cursor = pain.cursor()
    cursor.execute("SELECT prefix, start_id, current_id FROM id_generation where category_name='device' ")
    result = cursor.fetchone()
    if result:
        prefix, start_number, current_id = result
        dev_id = f"{prefix}{current_id}"
        new_current_id = int(current_id) + 1
        new_current_id_str = f"{new_current_id:03d}"
        cursor.execute("UPDATE id_generation SET current_id = %s where category_name='device' ",
                       (new_current_id_str,))

    if request.method == 'POST':
        user_id = request.form['user_id']
        password = request.form['password']
        encrypted_password = hash_password(password)
        device_name = request.form['device_name']
        mac_add = request.form['mac_add']
        dev_ins = request.form['dev_ins']
        time = user_time()
        ip = get_user_ip()
        username = session.get('username')
        device_add_sql = """INSERT INTO device_details(device_id, device_name, device_mac, device_username, 
        device_password, device_status, device_last_login_details, device_logged_in_ip, device_logged_in_location, 
        device_login_failure_attempts, device_allocated_for, device_created_by, device_created_timestamp, 
        device_created_ip ) VALUES(%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s) """
        device_add_val = (
            dev_id, device_name, mac_add, user_id, encrypted_password, 0, 0, 0, 0, 0, dev_ins, username, time, ip)
        cursor.execute(device_add_sql, device_add_val)
        pain.commit()
        flash("Device Configured Successfully..!")
    return redirect("/super_admin/devices")


@painmgmt.route('/device_update', methods=['POST', 'GET'])
def update():
    if request.method == 'POST':

        Device_Allocated_To = request.form["Device_Allocated_To"]
        Device_Id = request.form["Device_Id"]
        Device_Username = request.form["Device_Username"]
        Device_Name = request.form["Device_Name"]
        Device_Mac_Address = request.form["Device_Mac_Address"]
        last_login_detail = request.form["last_login_detail"]
        login_ip = request.form["login_ip"]
        login_location = request.form["login_location"]
        attempts = request.form["attempts"]
        # cur = cnx.cursor()
        cursor.execute(" UPDATE device_details SET device_allocated_for=%s, device_username=%s, device_name=%s, " \
                       " device_mac=%s, device_last_login_details=%s,device_logged_in_ip=%s, device_logged_in_location=%s," \
                       " device_login_failure_attempts=%s WHERE device_id=%s", (
                       Device_Allocated_To, Device_Username, Device_Name, Device_Mac_Address, last_login_detail,
                       login_ip, login_location, attempts, Device_Id))
        # flash("Data Updated Successfully")
        pain.commit()
        flash("Updated Successfully")
        return redirect("/super_admin/devices")
    else:
        return "error"

    return render_template("device_controller.html")


@painmgmt.route('/device_controller_delete/<dev_id>', methods=['POST'])
def dev_delete(dev_id):
    cursor.execute("SELECT prefix, start_id, current_id FROM id_generation where category_name='device' ")
    result = cursor.fetchone()
    if result:
        prefix, start_number, current_id = result
        device_id = f"{prefix}{current_id}"
        new_current_id = int(current_id) - 1
        new_current_id_str = f"{new_current_id:03d}"
        cursor.execute("UPDATE id_generation SET current_id = %s where category_name='device' ",
                       (new_current_id_str,))
    username = session.get('username')
    time = user_time()
    ip = get_user_ip()
    backup_insert_sql = "INSERT INTO PAIN_MANAGEMENT.device_details_backup (device_id, device_name, device_mac, " \
                        "device_username, device_password, device_status, device_last_login_details, " \
                        "device_logged_in_ip, device_logged_in_location, device_login_failure_attempts, " \
                        "device_allocated_for, device_deleted_by, device_deleted_timestamp, device_deleted_ip) SELECT " \
                        "device_id, device_name, device_mac, device_username, device_password, device_status, " \
                        "device_last_login_details, device_logged_in_ip, device_logged_in_location, " \
                        "device_login_failure_attempts, device_allocated_for, %s, %s, %s" \
                        " FROM PAIN_MANAGEMENT.device_details WHERE " \
                        "device_id = %s "
    cursor.execute(backup_insert_sql, (username, time, ip, dev_id))
    pain.commit()

    delete_device_sql = "DELETE FROM device_details WHERE device_id = %s"
    cursor.execute(delete_device_sql, (dev_id,))
    pain.commit()
    flash("Device Configurations Deleted Successfully..!")
    return redirect('/super_admin/devices')


@painmgmt.route('/api/login_check')#, methods=['POST'])
def login_api():
    global username, password
    if request.method == 'POST':
        # username = request.form['username']
        username = "Musaffar"
        # password = request.form['password']
        password = "msvr1234"
        device_sql = "SELECT device_username, device_password, device_status, device_login_failure_attempts FROM " \
                     "device_details WHERE binary device_username = %s and device_status=0"
        cursor.execute(device_sql, (username,))
        device = cursor.fetchone()
        if device:
            stored_hashed_password = device[1]
            current_attempts = int(device[3])
            if check_password(stored_hashed_password, password):
                time = user_time()
                ip = get_user_ip()
                location = get_user_location(ip)
                update_sql = "UPDATE device_details SET device_last_login_details = %s, device_logged_in_ip = %s, " \
                             "device_logged_in_location = %s WHERE device_username = %s "
                cursor.execute(update_sql, (time, ip, location, username))
                pain.commit()
                return "True"
            else:
                new_attempts = current_attempts + 1
                update_sql = "UPDATE device_details SET device_login_failure_attempts = %s WHERE device_username = %s "
                cursor.execute(update_sql, (new_attempts, username))
                pain.commit()
                if new_attempts > 3:
                    update_sql = "UPDATE device_details SET device_status = 2 WHERE device_username = %s "
                    cursor.execute(update_sql, (username,))
                    pain.commit()
                flash(f"Incorrect Password....! Limit Exceeds {current_attempts} of 3")
                return "Incorrect Password...!"
    else:
        flash("Invalid User/ Account Locked....!")
        return "Invalid User / Account Locked...!"


@painmgmt.route('/super_admin/users')
def users():
    ins_cltd_sql = "SELECT * FROM institution_details WHERE lock_status=0"
    cursor.execute(ins_cltd_sql)
    ins = cursor.fetchall()

    user_clctd_sql = "SELECT * FROM user_details"
    cursor.execute(user_clctd_sql)
    users = cursor.fetchall()
    return render_template("user_creation.html", users=users, ins=ins)


@painmgmt.route('/super_admin/user_creation', methods=['POST'])
def user_creation():
    if request.method == 'POST':
        ins = request.form['ins']
        u_name = request.form['u_name']
        password = request.form['password']
        encrypted_password = hash_password(password)
        role = request.form['role']
        time = user_time()
        ip = get_user_ip()
        username = session.get('username')
        user_add_sql = """INSERT INTO user_details(institution_name, user_id, password, role, lock_status, 
        last_login_details, logged_in_ip, number_of_failure_attempts, user_created_by, timestamp, ip_address) VALUES(
        %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s) """
        user_add_val = (ins, u_name, encrypted_password, role, 0, 0, 0, 0, username, time, ip)
        cursor.execute(user_add_sql, user_add_val)
        pain.commit()
        flash("User Created Successfully..!")
    return redirect("/super_admin/users")


@painmgmt.route('/admin/dashboard')
def adminDashboard():
    return render_template('admin_dashboard.html')


if __name__ == '__main__':
    painmgmt.run(debug=True)
