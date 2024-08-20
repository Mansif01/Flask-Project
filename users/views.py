# IMPORTS
import logging

from flask import Blueprint, render_template, flash, redirect, url_for, session, request
from markupsafe import Markup

from app import db
from models import User
from users.forms import RegisterForm, PasswordForm

from users.forms import LoginForm
from flask_login import login_user, logout_user, login_required, current_user
from datetime import datetime

# CONFIG
users_blueprint = Blueprint('users', __name__, template_folder='templates')


# VIEWS
# view registration
@users_blueprint.route('/register', methods=['GET', 'POST'])
def register():
    # create signup form object
    form = RegisterForm()

    # if request method is POST or form is valid
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        # if this returns a user, then the email already exists in database

        # if email already exists redirect user back to signup page with error message so user can try again
        if user:
            flash('Email address already exists')
            return render_template('users/register.html', form=form)

        # create a new user with the form data
        new_user = User(email=form.email.data,
                        firstname=form.firstname.data,
                        lastname=form.lastname.data,
                        phone=form.phone.data,
                        password=form.password.data,
                        role='user', date_of_birth=form.dateOfBirth.data, postcode=form.postcode.data)

        logging.warning('SECURITY - User registration [%s, %s]',
                        form.email.data,
                        request.remote_addr)

        # add the new user to the database
        db.session.add(new_user)
        db.session.commit()

        # sends user to login page
        session['email'] = new_user.email
        return redirect(url_for('users.setup_2fa'))
    # if request method is GET or form not valid re-render signup page
    return render_template('users/register.html', form=form)


# view user login
@users_blueprint.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()

    if not session.get('authentication_attempts'):
        session['authentication_attempts'] = 0

    if form.validate_on_submit():
        user = User.query.filter_by(email=form.username.data).first()

        # If the user not in database or the password, pin and postcode does not match with the ones in the database
        # then show invalid login in the log file and flash error messages and send the user to the login page.
        if not user or not user.verify_password(form.password.data) or not user.verify_pin(form.pin.data) or not user.verify_postcode(form.postcode.data):
            session['authentication_attempts'] += 1
            logging.warning('SECURITY - Invalid log in [%s, %s]',
                            form.username.data,
                            request.remote_addr)
            # If the user attempts to login with incorrect credentials for more than or equal to 3 times then the user
            # is redirected to reset page to reset.
            if session.get('authentication_attempts') >= 3:
                flash(Markup('Maximum number of incorrect login exceeded. Please click <a href="/reset">here</a> to '
                             'reset.'))
                return render_template('users/login.html')

            flash('Please check your login details and try again, {} login attempts remaining'.format(
                3 - session.get('authentication_attempts')))
            return render_template('users/login.html', form=form)

        login_user(user)

        logging.warning('SECURITY - Log in [%s, %s, %s]',
                        current_user.id,
                        current_user.email,
                        request.remote_addr)

        # The existing value of current_login is now the date and time of last_login
        current_user.last_login = current_user.current_login
        # Getting the date and time of current_login and then committing it.
        current_user.current_login = datetime.now()

        current_user.last_successful_login = current_user.current_successful_login
        current_user.current_successful_login = request.remote_addr
        current_user.total_login += 1

        db.session.commit()
        # If the role of the user is admin then admin page is shown otherwise lottery page is shown.
        if current_user.role == 'admin':
            return redirect(url_for('admin.admin'))
        else:
            return redirect(url_for('lottery.lottery'))
        # return redirect(url_for('main.index'))

    return render_template('users/login.html', form=form)


# view user account
@users_blueprint.route('/account')
@login_required
def account():
    return render_template('users/account.html',
                           acc_no="PLACEHOLDER FOR USER ID",
                           email="PLACEHOLDER FOR USER EMAIL",
                           firstname="PLACEHOLDER FOR USER FIRSTNAME",
                           lastname="PLACEHOLDER FOR USER LASTNAME",
                           phone="PLACEHOLDER FOR USER PHONE")



@users_blueprint.route('/setup_2fa')
def setup_2fa():
    if 'email' not in session:
        return redirect(url_for('index'))

    user = User.query.filter_by(email=session['email']).first()
    if not user:
        return redirect(url_for('index'))
    del session['email']

    return render_template('users/setup_2fa.html', email=user.email, uri=user.get_2fa_uri()), 200, {
        'Cache-Control': 'no-cache, no-store, must-revalidate',
        'Pragma': 'no-cache',
        'Expires': '0'
    }


@users_blueprint.route('/reset')
def reset():
    session['authentication_attempts'] = 0
    return redirect(url_for('users.login'))

# A logout function to log the user out
@users_blueprint.route('/logout')
@login_required
def logout():
    logging.warning('SECURITY - Log out [%s, %s, %s, %s]',
                    current_user.id,
                    current_user.email,
                    current_user.role,
                    request.remote_addr)
    logout_user()

    return redirect(url_for('index'))

# A function to update password
# if current password does not match the password stored in the database then show error messages
# If current password and new password are same then error messages shown.
# If both these condition are fulfilled then current password becomes the new password and stored in the database and
# the user is redirected to account page.
@users_blueprint.route('/update_password', methods=['GET', 'POST'])
def update_password():
    form = PasswordForm()

    if form.validate_on_submit():
        if not current_user.verify_password(form.current_password.data):
            flash('Current password is incorrect.')
            return redirect(url_for('users.update_password'))

        if current_user.verify_password(form.new_password.data):
            flash('New password must be different from the current password.')
            return redirect(url_for('users.update_password'))

        current_user.password = form.new_password.data
        db.session.commit()
        flash('Password changed successfully')

        return redirect(url_for('users.account'))

    return render_template('users/update_password.html', form=form)
