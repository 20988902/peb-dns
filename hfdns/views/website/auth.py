from flask import Blueprint, request, jsonify, current_app, redirect, render_template, flash, url_for
from flask_login import login_user, logout_user, login_required, current_user
from . import auth
from hfdns.extensions import db
from hfdns.models import User
from hfdns.forms.auth import LoginForm, RegistrationForm
from ldap3 import Server, Connection, ALL


auth = Blueprint('auth', __name__, url_prefix='/auth')


def auth_via_auth(username, passwd):
    try:
        server = Server(current_app.config.get('LDAP_SERVER'), port=int(current_app.config.get('LDAP_SERVER_PORT')), use_ssl=True, get_info=ALL)
        _connection = Connection(server, 'cn=' + username + current_app.config.get('LDAP_CONFIG'), passwd, auto_bind=True)
    except Exception as e:
        return False
    return True


@auth.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        if auth_via_auth(form.username.data.strip(), form.password.data):
            user = User.query.filter_by(username=form.username.data).first()
            if user is not None :
                login_user(user, form.remember_me.data)
                return redirect(request.args.get('next') or url_for('dns.index'))
            new_user = User(username=form.username.data)
            db.session.add(new_user)
            db.session.commit()
            login_user(new_user, form.remember_me.data)
            return redirect(request.args.get('next') or url_for('dns.index'))

        user = User.query.filter_by(username=form.username.data).first()
        if user is not None and user.verify_password(form.password.data):
            login_user(user, form.remember_me.data)
            return redirect(request.args.get('next') or url_for('dns.index'))
        
        flash('无效的用户名或密码!')
        return redirect(url_for('auth.login'))
    return render_template('auth/login.html', form=form)


@auth.route('/logout')
@login_required
def logout():
    logout_user()
    flash('你已经退出。')
    return redirect(url_for('auth.login'))


# 新添加简单的用户注册功能，2个小时赶出来的，有点糙，后续会改进
@auth.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        user_count = db.session.query(User).count()
        user = User(email=form.email.data,
                    username=form.username.data,
                    password=form.password.data)
        if user_count == 0:
            user.admin = 2
        db.session.add(user)
        db.session.commit()
        flash('注册成功，请用账号密码登录.')
        return redirect(url_for('auth.login'))
    return render_template('auth/register.html', form=form)
