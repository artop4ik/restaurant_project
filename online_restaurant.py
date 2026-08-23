import smtplib
import requests

from flask import Flask, json, jsonify, render_template, request, redirect, url_for, flash, session
from flask_login import login_required, current_user, login_user, logout_user # pip install flask-login
from flask_login import LoginManager

from functools import wraps

from online_restaurant_db import (
    Session, Users, Menu, Orders, Reservation,
    CATEGORIES, TABLE_TYPES
)
from datetime import datetime
from sqlalchemy import or_
from sqlalchemy.orm import joinedload


import os
import uuid
from email.mime.text import MIMEText

import secrets

from dotenv import load_dotenv
load_dotenv()  # reads variables from a local .env file, if present

app = Flask(__name__)

FILES_PATH = 'static/menu'

app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB
app.config['MAX_FORM_MEMORY_SIZE'] = 1024 * 1024  # 1MB
app.config['MAX_FORM_PARTS'] = 500

app.config['SESSION_COOKIE_SAMESITE'] = 'Strict'

SECRET_KEY = os.environ.get('SECRET_KEY')
if not SECRET_KEY:
    raise RuntimeError(
        'SECRET_KEY is not set. Create a .env file (see .env.example) '
        'or set the SECRET_KEY environment variable before running the app.'
    )

DATABASE_URL = os.getenv("DATABASE_URL")    
app.config['SECRET_KEY'] = SECRET_KEY


app.config['RESEND_API_KEY'] = os.environ.get('RESEND_API_KEY')

app.config['ADMIN_EMAIL'] = os.environ.get('ADMIN_EMAIL')




login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

@app.before_request
def ensure_csrf_token():
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_hex(16)

def admin_required(function):
    @wraps(function)
    @login_required
    def decorated_function(*args, **kwargs):

        if current_user.role != 'admin':
            return redirect(url_for('home'))

        return function(*args, **kwargs)

    return decorated_function

@login_manager.user_loader
def load_user(user_id):
    with Session() as session:
        user = session.query(Users).filter_by(id = user_id).first()
        if user:
            return user

@app.after_request
def apply_csp(response):
    nonce = secrets.token_urlsafe(16)  # Генеруємо випадковий nonce для дозволених скриптів
    csp = (
        f"default-src 'self'; "
        f"script-src 'self' 'nonce-{nonce}'; "
        f"style-src 'self'; "
        f"frame-ancestors 'none'; "
        f"base-uri 'self'; "
        f"form-action 'self'"
    )
    response.headers["Content-Security-Policy"] = csp
    response.set_cookie('nonce', nonce)
    return response


def validate_csrf():
    token = request.form.get("csrf_token")

    if not token:
        return False

    session_token = session.get("csrf_token")

    if not session_token:
        return False

    return secrets.compare_digest(token, session_token)

def get_cart_key():
    return f'cart_{current_user.id}'

    if not token or token != session.get("csrf_token"):
        return False

    return True

@app.route('/')
@app.route('/home')
def home():
    return render_template('home.html')


from sqlalchemy.exc import IntegrityError



def send_new_user_notification(user):

    """

    Надсилає адміну лист на email, коли реєструється новий користувач.

    Використовує Resend API (HTTPS), а не SMTP, бо багато хостингів

    (зокрема Render) блокують вихідні SMTP-з'єднання.

    Помилка надсилання не повинна ламати процес реєстрації,

    тому все загорнуто в try/except, а запит має timeout.

    """

    print('DEBUG: send_new_user_notification called for', user.nickname, flush=True)



    if not app.config['RESEND_API_KEY'] or not app.config['ADMIN_EMAIL']:

        print('DEBUG: RESEND_API_KEY or ADMIN_EMAIL missing, skipping send', flush=True)

        return



    try:

        body = (

            f"На сайті зареєструвався новий користувач.\n\n"

            f"ID: {user.id}\n"

            f"Nickname: {user.nickname}\n"

            f"Email: {user.email}\n"

        )



        response = requests.post(

            'https://api.resend.com/emails',

            headers={

                'Authorization': f'Bearer {app.config["RESEND_API_KEY"]}',

                'Content-Type': 'application/json',

            },

            json={

                # Без верифікованого власного домену Resend дозволяє

                # відправляти листи лише з onboarding@resend.dev.

                'from': 'onboarding@resend.dev',

                'to': [app.config['ADMIN_EMAIL']],

                'subject': f'Новий користувач: {user.nickname}',

                'text': body,

            },

            timeout=10,

        )



        print('DEBUG: Resend response', response.status_code, response.text, flush=True)



    except Exception as e:

        print('ERROR sending new user email:', repr(e), flush=True)

        
@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":

        if not validate_csrf():
            return "Запит заблоковано!", 403

        nickname = request.form.get("nickname", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")

        # Проверяем пустые поля
        if not nickname or not email or not password:
            flash("Заповніть усі поля!", "danger")

            return render_template(
                "register.html",
                csrf_token=session["csrf_token"]
            )

        # Проверка длины ника
        if len(nickname) < 3 or len(nickname) > 30:
            flash("Нікнейм має містити від 3 до 30 символів!", "danger")

            return render_template(
                "register.html",
                csrf_token=session["csrf_token"]
            )

        # Простая проверка email
        if "@" not in email or "." not in email.split("@")[-1]:
            flash("Введіть коректний email!", "danger")

            return render_template(
                "register.html",
                csrf_token=session["csrf_token"]
            )

        with Session() as cursor:

            # Проверяем существующий email
            existing_email = (
                cursor.query(Users)
                .filter_by(email=email)
                .first()
            )

            if existing_email:
                flash(
                    "Цей email вже використовується!",
                    "danger"
                )

                return render_template(
                    "register.html",
                    csrf_token=session["csrf_token"]
                )

            # Проверяем существующий nickname
            existing_nickname = (
                cursor.query(Users)
                .filter_by(nickname=nickname)
                .first()
            )

            if existing_nickname:
                flash(
                    "Цей нікнейм вже зайнятий!",
                    "danger"
                )

                return render_template(
                    "register.html",
                    csrf_token=session["csrf_token"]
                )

            # Создаём пользователя
            new_user = Users(
                nickname=nickname,
                email=email,
                role="user"
            )

            new_user.set_password(password)

            cursor.add(new_user)

            try:
                cursor.commit()
                cursor.refresh(new_user)

                send_new_user_notification(new_user)

            except IntegrityError:
                cursor.rollback()

                flash(
                    "Такий email або нікнейм вже використовується!",
                    "danger"
                )

                return render_template(
                    "register.html",
                    csrf_token=session["csrf_token"]
                )

            login_user(new_user)

            return redirect(url_for("home"))

    return render_template(
        "register.html",
        csrf_token=session["csrf_token"]
    )


@app.route("/login", methods = ["GET","POST"])
def login():
    if request.method == 'POST':
        if not validate_csrf():
            return "Запит заблоковано!", 403

        nickname = request.form['nickname']
        password = request.form['password']

        with Session() as cursor:
            user = cursor.query(Users).filter_by(nickname = nickname).first()
            if user and user.check_password(password):
                login_user(user)
                return redirect(url_for('home'))

            flash('Неправильний nickname або пароль!', 'danger')

    return render_template('login.html', csrf_token=session["csrf_token"])

@app.route("/logout", methods=["POST", "GET"])
@login_required
def logout():
    if not validate_csrf():
        return "Запит заблоковано!", 403

    logout_user()

    return redirect(url_for('login'))

@app.route("/add_position", methods=['GET', 'POST'])
@login_required
@admin_required
def add_position():

    if request.method == "POST":
        if not validate_csrf():
            return "Запит заблоковано!", 403

        name = request.form['name']
        file = request.files.get('img')
        ingredients = request.form['ingredients']
        description = request.form['description']
        price = request.form['price']
        weight = request.form['weight']
        category = request.form.get('category')

        if category not in CATEGORIES:
            flash('Оберіть коректну категорію!', 'danger')
            return render_template('add_position.html', csrf_token=session["csrf_token"], categories=CATEGORIES)

        if not file or not file.filename:
            return 'Файл не вибрано або завантаження не вдалося'

        unique_filename = f"{uuid.uuid4()}_{file.filename}"
        output_path = os.path.join('static/menu', unique_filename)

        with open(output_path, 'wb') as f:
            f.write(file.read())

        with Session() as cursor:
            new_position = Menu(name=name, ingredients=ingredients, description=description,
                                price=price, weight=weight, file_name=unique_filename, category=category)
            cursor.add(new_position)
            cursor.commit()

        flash('Позицію додано успішно!')

    return render_template('add_position.html', csrf_token=session["csrf_token"], categories=CATEGORIES)


@app.route('/admin/menu')
@login_required
@admin_required
def admin_menu():
    with Session() as cursor:
        all_positions = (
            cursor.query(Menu)
            .order_by(Menu.category, Menu.name)
            .all()
        )

    return render_template(
        'admin_menu.html',
        all_positions=all_positions,
        categories=CATEGORIES
    )


@app.route('/admin/menu/edit/<int:menu_id>', methods=['GET', 'POST'])
@login_required
@admin_required
def edit_position(menu_id):
    with Session() as cursor:
        position = cursor.query(Menu).filter_by(id=menu_id).first()

        if not position:
            flash('Позицію не знайдено.', 'danger')
            return redirect(url_for('admin_menu'))

        if request.method == 'POST':
            if not validate_csrf():
                return "Запит заблоковано!", 403

            name = request.form.get('name', '').strip()
            ingredients = request.form.get('ingredients', '').strip()
            description = request.form.get('description', '').strip()
            price = request.form.get('price')
            weight = request.form.get('weight', '').strip()
            category = request.form.get('category')
            file = request.files.get('img')

            if category not in CATEGORIES:
                flash('Оберіть коректну категорію!', 'danger')
                return render_template(
                    'edit_position.html',
                    csrf_token=session["csrf_token"],
                    categories=CATEGORIES,
                    position=position
                )

            if not name or not ingredients or not description or not weight:
                flash('Заповніть усі обов\'язкові поля!', 'danger')
                return render_template(
                    'edit_position.html',
                    csrf_token=session["csrf_token"],
                    categories=CATEGORIES,
                    position=position
                )

            try:
                price = float(price)
                if price < 0:
                    raise ValueError
            except (ValueError, TypeError):
                flash('Вкажіть коректну ціну!', 'danger')
                return render_template(
                    'edit_position.html',
                    csrf_token=session["csrf_token"],
                    categories=CATEGORIES,
                    position=position
                )

            position.name = name
            position.ingredients = ingredients
            position.description = description
            position.price = price
            position.weight = weight
            position.category = category

            if file and file.filename:
                unique_filename = f"{uuid.uuid4()}_{file.filename}"
                output_path = os.path.join('static/menu', unique_filename)

                with open(output_path, 'wb') as f:
                    f.write(file.read())

                position.file_name = unique_filename

            cursor.commit()
            flash('Позицію оновлено успішно!', 'success')
            return redirect(url_for('admin_menu'))

        return render_template(
            'edit_position.html',
            csrf_token=session["csrf_token"],
            categories=CATEGORIES,
            position=position
        )


@app.route('/admin/menu/toggle/<int:menu_id>', methods=['POST'])
@login_required
@admin_required
def toggle_menu_item(menu_id):
    if not validate_csrf():
        return "Запит заблоковано!", 403

    with Session() as cursor:
        position = cursor.query(Menu).filter_by(id=menu_id).first()

        if not position:
            flash('Позицію не знайдено.', 'danger')
            return redirect(url_for('admin_menu'))

        position.active = not position.active
        cursor.commit()

        flash(
            'Позицію активовано.' if position.active else 'Позицію вимкнено з меню.',
            'success'
        )

    return redirect(url_for('admin_menu'))


@app.route('/admin/menu/delete/<int:menu_id>', methods=['POST'])
@login_required
@admin_required
def delete_menu_item(menu_id):
    if not validate_csrf():
        return "Запит заблоковано!", 403

    with Session() as cursor:
        position = cursor.query(Menu).filter_by(id=menu_id).first()

        if not position:
            flash('Позицію не знайдено.', 'danger')
            return redirect(url_for('admin_menu'))

        if position.file_name:
            file_path = os.path.join('static/menu', position.file_name)
            if os.path.exists(file_path):
                os.remove(file_path)

        cursor.delete(position)
        cursor.commit()

    flash('Позицію видалено назавжди.', 'success')
    return redirect(url_for('admin_menu'))


@app.route('/menu')
def menu():
    selected_category = request.args.get('category', '').strip()
    search_query = request.args.get('q', '').strip()

    with Session() as cursor:
        query = cursor.query(Menu).filter_by(active=True)

        if selected_category and selected_category in CATEGORIES:
            query = query.filter(Menu.category == selected_category)

        if search_query:
            like_pattern = f"%{search_query}%"
            query = query.filter(
                or_(
                    Menu.name.ilike(like_pattern),
                    Menu.ingredients.ilike(like_pattern)
                )
            )

        all_positions = query.all()

    return render_template(
        'menu.html',
        all_positions=all_positions,
        categories=CATEGORIES,
        selected_category=selected_category,
        search_query=search_query
    )
@app.route('/cart')
@login_required
def cart():
    cart_key = get_cart_key()
    cart_data = session.get(cart_key, {})

    cart_items = []
    total_price = 0

    with Session() as cursor:
        for menu_id, quantity in cart_data.items():

            item = cursor.query(Menu).filter_by(
                id=int(menu_id),
                active=True
            ).first()

            if not item:
                continue

            item_total = float(item.price) * quantity

            cart_items.append({
                'item': item,
                'quantity': quantity,
                'total': item_total
            })

            total_price += item_total

    return render_template(
        'cart.html',
        cart_items=cart_items,
        total_price=total_price
    )

@app.route('/cart/add/<int:menu_id>', methods=['POST'])
@login_required
def add_to_cart(menu_id):

    if not validate_csrf():
        return "Запит заблоковано!", 403

    cart_key = get_cart_key()
    cart = session.get(cart_key, {})

    menu_id = str(menu_id)

    if menu_id in cart:
        cart[menu_id] += 1
    else:
        cart[menu_id] = 1

    session[cart_key] = cart
    session.modified = True

    flash('Позицію успішно додано до кошика!', 'success')

    return redirect(url_for('menu'))

@app.route('/cart/increase/<int:menu_id>', methods=['POST'])
@login_required
def increase_cart(menu_id):

    if not validate_csrf():
        return "Запит заблоковано!", 403

    cart_key = get_cart_key()
    cart = session.get(cart_key, {})

    menu_id = str(menu_id)

    if menu_id in cart:
        cart[menu_id] += 1

    session[cart_key] = cart
    session.modified = True

    return redirect(url_for('cart'))
@app.route('/cart/decrease/<int:menu_id>', methods=['POST'])
@login_required
def decrease_from_cart(menu_id):

    if not validate_csrf():
        return "Запит заблоковано!", 403

    cart_key = get_cart_key()
    cart = session.get(cart_key, {})

    menu_id = str(menu_id)

    if menu_id in cart:

        cart[menu_id] -= 1

        if cart[menu_id] <= 0:
            del cart[menu_id]

    session[cart_key] = cart
    session.modified = True

    return redirect(url_for('cart'))

@app.route('/cart/remove/<int:menu_id>', methods=['POST'])
@login_required
def remove_from_cart(menu_id):

    if not validate_csrf():
        return "Запит заблоковано!", 403

    cart_key = get_cart_key()
    cart = session.get(cart_key, {})

    menu_id = str(menu_id)

    if menu_id in cart:
        del cart[menu_id]

    session[cart_key] = cart
    session.modified = True

    return redirect(url_for('cart'))

@app.route('/admin')
@login_required
@admin_required
def admin():
    

    with Session() as cursor:
        menu_count = cursor.query(Menu).filter_by(active=True).count()
        orders_count = cursor.query(Orders).count()

    return render_template(
        'admin.html',
        menu_count=menu_count,
        orders_count=orders_count
    )


@app.route('/admin/orders', methods=['GET'])
@login_required
@admin_required
def admin_orders():
  
    with Session() as cursor:
        orders = (
            cursor.query(Orders)
            .options(joinedload(Orders.user))
            .order_by(Orders.order_time.desc())
            .all()
        )
        

    return render_template(
        'admin_orders.html',
        orders=orders,
    )

@app.route('/my_orders')
@login_required
def my_orders():

    with Session() as cursor:

        orders = (
            cursor.query(Orders)
            .filter_by(user_id=current_user.id)
            .order_by(Orders.order_time.desc())
            .all()
        )

        prepared_orders = []

        for order in orders:

            try:
                order_data = json.loads(order.order_list)
            except (json.JSONDecodeError, TypeError):
                order_data = {
                    'items': [],
                    'total_price': 0
                }

            prepared_orders.append({
                'id': order.id,
                'order_time': order.order_time,
                'items': order_data.get('items', []),
                'total_price': order_data.get('total_price', 0),
                'payment_method': order_data.get(
                    'payment_method',
                    'Не вказано'
                ),
                'address': order_data.get(
                    'address',
                    'Не вказано'
                ),
                'status': order.status
            })

    return render_template(
        'my_orders.html',
        orders=prepared_orders
    )

@app.route('/checkout', methods=['GET', 'POST'])
@login_required
def checkout():

    cart_key = get_cart_key()
    cart_data = session.get(cart_key, {})

    if not cart_data:
        flash('Ваш кошик порожній.', 'warning')
        return redirect(url_for('menu'))

    total_price = 0

    with Session() as cursor:

        for menu_id, quantity in cart_data.items():

            item = cursor.query(Menu).filter_by(
                id=int(menu_id),
                active=True
            ).first()

            if item:
                total_price += float(item.price) * quantity


    if request.method == 'POST':

        if request.form.get("csrf_token") != session.get("csrf_token"):
            return "Запит заблоковано!", 403

        name = request.form.get('name')
        phone = request.form.get('phone')
        address = request.form.get('address')
        payment_method = request.form.get('payment_method')


        order_items = []

        with Session() as cursor:

            for menu_id, quantity in cart_data.items():

                item = cursor.query(Menu).filter_by(
                    id=int(menu_id),
                    active=True
                ).first()

                if not item:
                    continue

                order_items.append({
                    'menu_id': item.id,
                    'name': item.name,
                    'quantity': quantity,
                    'price': float(item.price)
                })


            order_data = {
                'customer_name': name,
                'phone': phone,
                'address': address,
                'payment_method': payment_method,
                'total_price': total_price,
                'items': order_items
            }


            new_order = Orders(
                order_list=json.dumps(
                    order_data,
                    ensure_ascii=False
                ),
                order_time=datetime.now(),
                user_id=current_user.id,
                status='paid' if payment_method == 'card' else 'pending',
                total_price=total_price
            )

            cursor.add(new_order)
            cursor.commit()


        # Очищаем корзину после успешного создания заказа
        session.pop(cart_key, None)

        flash(
            'Замовлення успішно оформлено! 🎉',
            'success'
        )

        return redirect(url_for('my_orders'))


    return render_template(
        'payment.html',
        total_price=total_price
    )

@app.route('/my_orders/cancel/<int:order_id>', methods=['POST'])
@login_required
def cancel_order(order_id):

    if not validate_csrf():
        return "Запит заблоковано!", 403

    with Session() as cursor:

        order = (
            cursor.query(Orders)
            .filter_by(
                id=order_id,
                user_id=current_user.id
            )
            .first()
        )

        if not order:
            flash('Замовлення не знайдено.', 'danger')
            return redirect(url_for('my_orders'))

        if order.status == 'cancelled':
            flash('Це замовлення вже скасовано.', 'warning')
            return redirect(url_for('my_orders'))

       

        order.status = 'cancelled'

        cursor.commit()

    flash('Замовлення успішно скасовано.', 'success')

    return redirect(url_for('my_orders'))


@app.route('/reservation', methods=['GET', 'POST'])
@login_required
def reservation():
    if request.method == 'POST':

        if not validate_csrf():
            return "Запит заблоковано!", 403

        time_start_raw = request.form.get('time_start')
        type_table = request.form.get('type_table')
        guests = request.form.get('guests')

        if type_table not in TABLE_TYPES:
            flash('Оберіть коректний тип столика!', 'danger')
            return render_template('reservation.html', csrf_token=session["csrf_token"], table_types=TABLE_TYPES)

        try:
            time_start = datetime.fromisoformat(time_start_raw)
        except (ValueError, TypeError):
            flash('Вкажіть коректну дату та час бронювання!', 'danger')
            return render_template('reservation.html', csrf_token=session["csrf_token"], table_types=TABLE_TYPES)

        if time_start <= datetime.now():
            flash('Час бронювання має бути у майбутньому!', 'danger')
            return render_template('reservation.html', csrf_token=session["csrf_token"], table_types=TABLE_TYPES)

        try:
            guests = int(guests)
            if guests < 1 or guests > 20:
                raise ValueError
        except (ValueError, TypeError):
            flash('Вкажіть коректну кількість гостей (1-20)!', 'danger')
            return render_template('reservation.html', csrf_token=session["csrf_token"], table_types=TABLE_TYPES)

        with Session() as cursor:
            new_reservation = Reservation(
                time_start=time_start,
                type_table=type_table,
                guests=guests,
                status='pending',
                user_id=current_user.id
            )
            cursor.add(new_reservation)
            cursor.commit()

        flash('Столик успішно заброньовано! Очікуйте підтвердження.', 'success')
        return redirect(url_for('my_reservations'))

    return render_template('reservation.html', csrf_token=session["csrf_token"], table_types=TABLE_TYPES)


@app.route('/my_reservations')
@login_required
def my_reservations():
    with Session() as cursor:
        reservations = (
            cursor.query(Reservation)
            .options(joinedload(Reservation.user))
            .filter_by(user_id=current_user.id)
            .order_by(Reservation.time_start.desc())
            .all()
        )

    return render_template('my_reservations.html', reservations=reservations)


@app.route('/reservation/cancel/<int:reservation_id>', methods=['POST'])
@login_required
def cancel_reservation(reservation_id):
    if not validate_csrf():
        return "Запит заблоковано!", 403

    with Session() as cursor:
        res = (
            cursor.query(Reservation)
            .filter_by(id=reservation_id, user_id=current_user.id)
            .first()
        )

        if not res:
            flash('Бронювання не знайдено.', 'danger')
            return redirect(url_for('my_reservations'))

        if res.status == 'cancelled':
            flash('Це бронювання вже скасовано.', 'warning')
            return redirect(url_for('my_reservations'))

        res.status = 'cancelled'
        cursor.commit()

    flash('Бронювання успішно скасовано.', 'success')
    return redirect(url_for('my_reservations'))


@app.route('/admin/reservations')
@login_required
@admin_required
def admin_reservations():
   

    with Session() as cursor:
        reservations = (
            cursor.query(Reservation)
            .options(joinedload(Reservation.user))
            .order_by(Reservation.time_start.desc())
            .all()
        )

    return render_template('admin_reservations.html', reservations=reservations)


@app.route('/admin/reservations/confirm/<int:reservation_id>', methods=['POST'])
@login_required
@admin_required
def admin_confirm_reservation(reservation_id):
    if not validate_csrf():
        return "Запит заблоковано!", 403

    with Session() as cursor:
        res = cursor.query(Reservation).filter_by(id=reservation_id).first()

        if not res:
            flash('Бронювання не знайдено.', 'danger')
            return redirect(url_for('admin_reservations'))

        if res.status == 'cancelled':
            flash('Скасоване бронювання не можна підтвердити.', 'warning')
            return redirect(url_for('admin_reservations'))

        res.status = 'confirmed'
        cursor.commit()

    flash('Бронювання підтверджено.', 'success')
    return redirect(url_for('admin_reservations'))


@app.route('/admin/reservations/cancel/<int:reservation_id>', methods=['POST'])
@login_required
@admin_required
def admin_cancel_reservation(reservation_id):
    if not validate_csrf():
        return "Запит заблоковано!", 403

    with Session() as cursor:
        res = cursor.query(Reservation).filter_by(id=reservation_id).first()

        if not res:
            flash('Бронювання не знайдено.', 'danger')
            return redirect(url_for('admin_reservations'))

        res.status = 'cancelled'
        cursor.commit()

    flash('Бронювання скасовано.', 'success')
    return redirect(url_for('admin_reservations'))

@app.route('/admin/users')

@login_required

@admin_required

def admin_users():



    with Session() as cursor:

        users = (

            cursor.query(Users)

            .order_by(Users.id)

            .all()

        )



    return render_template('admin_users.html', users=users)






if __name__ == '__main__':
    app.run