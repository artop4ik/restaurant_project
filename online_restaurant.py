from flask import Flask, json, jsonify, render_template, request, redirect, url_for, flash, session
from flask_login import login_required, current_user, login_user, logout_user # pip install flask-login
from flask_login import LoginManager

from functools import wraps

from online_restaurant_db import Session, Users, Menu, Orders, Reservation
from datetime import datetime

import os
import uuid

import secrets

app = Flask(__name__)

FILES_PATH = 'static/menu'

app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB
app.config['MAX_FORM_MEMORY_SIZE'] = 1024 * 1024  # 1MB
app.config['MAX_FORM_PARTS'] = 500

app.config['SESSION_COOKIE_SAMESITE'] = 'Strict'
app.config['SECRET_KEY'] = '#cv)3v7w$*s3fk;5c!@y0?:?№3"9)#'

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

    if not token or token != session.get("csrf_token"):
        return False

    return True

@app.route('/')
@app.route('/home')
def home():
    return render_template('home.html')


@app.route("/register", methods = ['GET','POST'])
def register():
    if request.method == 'POST':
        if not validate_csrf():
            return "Запит заблоковано!", 403
        nickname = request.form['nickname']
        email = request.form['email']
        password = request.form['password']

        with Session() as cursor:
            if cursor.query(Users).filter_by(email=email).first() or cursor.query(Users).filter_by(nickname = nickname).first():
                flash('Користувач з таким email або нікнеймом вже існує!', 'danger')
                return render_template('register.html',csrf_token=session["csrf_token"])

            new_user = Users(nickname=nickname, email=email)
            new_user.set_password(password)
            cursor.add(new_user)
            cursor.commit()
            cursor.refresh(new_user)
            login_user(new_user)
            return redirect(url_for('home'))
    return render_template('register.html',csrf_token=session["csrf_token"])


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

@app.route("/logout", methods=["POST"])
@login_required
def logout():
    if not validate_csrf():
        return "Запит заблоковано!", 403

    logout_user()

    return jsonify({
        "success": True,
        "message": "Logged out"
    })

@app.route("/add_position", methods=['GET', 'POST'])
@login_required
@admin_required
def add_position():
    if current_user.role != 'admin':
        return redirect(url_for('home'))

    if request.method == "POST":
        if not validate_csrf():
            return "Запит заблоковано!", 403

        name = request.form['name']
        file = request.files.get('img')
        ingredients = request.form['ingredients']
        description = request.form['description']
        price = request.form['price']
        weight = request.form['weight']

        if not file or not file.filename:
            return 'Файл не вибрано або завантаження не вдалося'

        unique_filename = f"{uuid.uuid4()}_{file.filename}"
        output_path = os.path.join('static/menu', unique_filename)

        with open(output_path, 'wb') as f:
            f.write(file.read())

        with Session() as cursor:
            new_position = Menu(name=name, ingredients=ingredients, description=description,
                                price=price, weight=weight, file_name=unique_filename)
            cursor.add(new_position)
            cursor.commit()

        flash('Позицію додано успішно!')

    return render_template('add_position.html', csrf_token=session["csrf_token"])
@app.route('/menu')
def menu():
    with Session() as session:
        all_positions = session.query(Menu).filter_by(active = True).all()
    return render_template('menu.html',all_positions = all_positions)

@app.route('/cart')
@login_required
def cart():
    cart_data = session.get('cart', {})

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

    cart = session.get('cart', {})

    menu_id = str(menu_id)

    if menu_id in cart:
        cart[menu_id] += 1
    else:
        cart[menu_id] = 1

    session['cart'] = cart
    session.modified = True

    # ВАЖНО:
    # после добавления возвращаем пользователя именно в меню
    flash('Позицію успішно додано до кошика!', 'success')

    return redirect(url_for('menu'))


@app.route('/cart/increase/<int:menu_id>', methods=['POST'])
@login_required
def increase_cart(menu_id):

    if request.form.get("csrf_token") != session.get("csrf_token"):
        return "Запит заблоковано!", 403

    cart = session.get('cart', {})

    menu_id = str(menu_id)

    if menu_id in cart:
        cart[menu_id] += 1

    session['cart'] = cart
    session.modified = True

    return redirect(url_for('cart'))


@app.route('/cart/decrease/<int:menu_id>', methods=['POST'])
@login_required
def decrease_from_cart(menu_id):

    if not validate_csrf():
        return "Запит заблоковано!", 403
    cart = session.get('cart', {})

    menu_id = str(menu_id)

    if menu_id in cart:

        cart[menu_id] -= 1

        if cart[menu_id] <= 0:
            del cart[menu_id]

    session['cart'] = cart
    session.modified = True

    return redirect(url_for('cart'))


@app.route('/cart/remove/<int:menu_id>', methods=['POST'])
@login_required
def remove_from_cart(menu_id):

    if request.form.get("csrf_token") != session.get("csrf_token"):
        return "Запит заблоковано!", 403

    cart = session.get('cart', {})

    menu_id = str(menu_id)

    if menu_id in cart:
        del cart[menu_id]

    session['cart'] = cart
    session.modified = True

    return redirect(url_for('cart'))

@app.route('/admin')
@login_required
@admin_required
def admin():
    if current_user.role != 'admin':
        return redirect(url_for('home'))

    with Session() as cursor:
        menu_count = cursor.query(Menu).filter_by(active=True).count()
        orders_count = cursor.query(Orders).count()

    return render_template(
        'admin.html',
        menu_count=menu_count,
        orders_count=orders_count
    )


@app.route('/admin/orders')
@login_required
@admin_required
def admin_orders():
    if current_user.role != 'admin':
        return redirect(url_for('home'))

    with Session() as cursor:
        orders = cursor.query(Orders).order_by(Orders.order_time.desc()).all()

    return render_template(
        'admin_orders.html',
        orders=orders
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

    cart_data = session.get('cart', {})

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
                status='paid' if payment_method == 'online' else 'pending'
            )

            cursor.add(new_order)
            cursor.commit()


        # Очищаем корзину после успешного создания заказа
        session.pop('cart', None)

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

        if order.status == 'paid':
            flash(
                'Оплачене замовлення не можна скасувати через цей розділ.',
                'warning'
            )
            return redirect(url_for('my_orders'))

        order.status = 'cancelled'

        cursor.commit()

    flash('Замовлення успішно скасовано.', 'success')

    return redirect(url_for('my_orders'))




if __name__ == '__main__':
    app.run(debug=True)