from app import app
from flask import render_template, flash, redirect, request, url_for
from flask_login import current_user, login_user, logout_user, login_required
from app.models import User, Snip
from app.forms import RegistrationForm, LoginForm, EditUserForm, ResetPasswordForm, ResetPasswordRequestForm, CreateSnipForm
from app.email import send_password_reset_email
from werkzeug.urls import url_parse
from app import db

@app.route('/')
@app.route('/index')
def index():
    return render_template('index.html', title="Home")

@app.route('/register', methods=['GET','POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    form = RegistrationForm()
    if form.validate_on_submit():
        user = User(username=form.username.data, name=form.name.data, email=form.email.data)
        user.set_password(form.password.data)
        db.session.add(user)
        db.session.commit()
        flash('Congratulations, your account has been created.')
        return redirect(url_for('login'))
    return render_template('register.html', title="Register", form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user is None or not user.check_password(form.password.data):
            flash('Invalid username or password')
            return redirect(url_for('login'))
        login_user(user, remember=form.remember_me.data)
        next_page = request.args.get('next')
        if not next_page or url_parse(next_page).netloc != '':
            next_page = url_for('index')
        return redirect(next_page)
    return render_template('login.html', title='Sign In', form=form)

@app.route('/user/<username>')
@login_required
def user(username):
    if current_user.username!=username:
        return redirect(url_for('index'))
    user = User.query.filter_by(username=username).first_or_404()
    page = request.args.get('page', 1, type=int)
    snips = Snip.query.filter_by(user_id=user.id).order_by(Snip.timestamp.desc()).paginate(page=page, per_page=2)
    next_url = url_for('user',username=current_user.username, page=snips.next_num) \
        if snips.has_next else None
    prev_url = url_for('user', username=current_user.username,page=snips.prev_num) \
        if snips.has_prev else None
    return render_template('user.html', user=user, snips=snips, next_url=next_url, prev_url=prev_url)

@app.route('/edit_user', methods=['GET','POST'])
@login_required
def edit_user():
    form = EditUserForm(current_user.username)
    if form.validate_on_submit():
        current_user.username = form.username.data
        current_user.name = form.name.data
        current_user.about_me = form.about_me.data
        db.session.commit()
        flash("Your profile changes have been saved.")
        return redirect(url_for('user', username=current_user.username))
    elif request.method == 'GET':
        form.username.data = current_user.username
        form.name.data = current_user.name
        form.about_me.data = current_user.about_me
    return render_template('edit_user.html', title="Edit Profile", form=form)

@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('index'))

@app.route('/reset_password_request', methods=['GET', 'POST'])
def reset_password_request():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    form = ResetPasswordRequestForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user:
            send_password_reset_email(user)
        flash('Check your email for the instructions to reset your password')
        return redirect(url_for('login'))
    return render_template('reset_password_request.html',
                           title='Reset Password', form=form)

@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    user = User.verify_reset_password_token(token)
    if not user:
        return redirect(url_for('index'))
    form = ResetPasswordForm()
    if form.validate_on_submit():
        user.set_password(form.password.data)
        db.session.commit()
        flash('Your password has been reset.')
        return redirect(url_for('login'))
    return render_template('reset_password.html', form=form)

@app.route('/snip/create', methods=['GET','POST'])
@login_required
def create_snip():
    form = CreateSnipForm()
    if form.validate_on_submit():
        snip = Snip(title=form.title.data, description=form.description.data, code=form.code.data, user_id=current_user.id)
        db.session.add(snip)
        db.session.commit()
        flash('Congratulations, your snippet has been created.')
        return redirect(url_for('snip', id=snip.id))
    return render_template('createSnip.html', title="Create Snip", form=form)

@app.route('/explore')
def explore():
    page = request.args.get('page', 1, type=int)
    snips = Snip.query.order_by(Snip.timestamp.desc()).paginate(page=page, per_page=2)
    next_url = url_for('explore', page=snips.next_num) \
        if snips.has_next else None
    prev_url = url_for('explore', page=snips.prev_num) \
        if snips.has_prev else None
    return render_template('snip.html', title="Snippets", snips=snips, next_url=next_url, prev_url=prev_url)