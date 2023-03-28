# __________________________________IMPORTS_______________________

from flask import Flask, render_template, redirect, url_for, request, flash, session
from flask_login import LoginManager, UserMixin, login_user, logout_user, current_user, login_required
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_wtf import FlaskForm
from wtforms import StringField, IntegerField, FloatField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Email
from email_validator import validate_email, EmailNotValidError

# __________________________________APP_______________________

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///ticket_show.sqlite3'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'secret_key'

# __________________________________DATABASE_______________________

db = SQLAlchemy(app)
app.app_context().push()

# __________________________________LOGIN_MANGER_______________________

login_manager = LoginManager()
login_manager.login_view = 'login'
login_manager.init_app(app)


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# __________________________________FORMS_______________________


class SignupForm(FlaskForm):
    name = StringField('Name', validators=[DataRequired()])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    confirm = PasswordField('Confirm Password')
    submit = SubmitField('Sign up')


class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')


class VenueForm(FlaskForm):
    name = StringField('Name', validators=[DataRequired()])
    place = StringField('Place', validators=[DataRequired()])
    capacity = IntegerField('Capacity', validators=[DataRequired()])
    submit = SubmitField('Add Venue')


class ShowForm(FlaskForm):
    name = StringField('Name', validators=[DataRequired()])
    rating = FloatField('Rating', validators=[DataRequired()])
    tags = StringField('Tags', validators=[DataRequired()])
    ticket_price = FloatField('Ticket Price', validators=[DataRequired()])
    venue_id = IntegerField('Venue ID', validators=[DataRequired()])
    submit = SubmitField('Add Show')


class BookingForm(FlaskForm):
    show_id = IntegerField('Show ID', validators=[DataRequired()])
    user_id = IntegerField('User ID', validators=[DataRequired()])
    seats = IntegerField('Seats', validators=[DataRequired()])
    submit = SubmitField('Book Show')


class SearchForm(FlaskForm):
    search = StringField('Search', validators=[DataRequired()])
    search_by = StringField('Search By', validators=[DataRequired()])
    submit = SubmitField('Search')


class DeleteForm(FlaskForm):
    submit = SubmitField('Delete', validators=[DataRequired()])

# __________________________________MODELS_______________________


class User(db.Model, UserMixin):
    __tablename__ = "user"
    user_id = db.Column(db.Integer, autoincrement=True, primary_key=True)
    name = db.Column(db.String(255), nullable=False)
    email = db.Column(db.String(255), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    is_admin = db.Column(db.Boolean, default=False, nullable=False)
    bookings = db.relationship('Booking', backref='user', lazy=True)

    def __repr__(self):
        return f'<User {self.name}>'

    def get_id(self):
        return self.user_id

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def verify_password(self, password):
        return check_password_hash(self.password_hash, password)


class Venue(db.Model):
    __tablename__ = "venue"
    venue_id = db.Column(db.Integer, autoincrement=True, primary_key=True)
    name = db.Column(db.String(255), nullable=False)
    place = db.Column(db.String(255), nullable=False)
    capacity = db.Column(db.Integer, nullable=False)
    seats_booked = db.Column(db.Integer, default=0, nullable=False)
    shows = db.relationship('Show', backref='venue', lazy=True)

    def __repr__(self):
        return f'<Venue {self.name}>'


class Show(db.Model):
    __tablename__ = "show"
    show_id = db.Column(db.Integer, autoincrement=True, primary_key=True)
    name = db.Column(db.String(255), nullable=False)
    rating = db.Column(db.Float(precision=1), nullable=False)
    tags = db.Column(db.String(255), nullable=False)
    ticket_price = db.Column(db.Float, nullable=False)
    venue_id = db.Column(db.Integer, db.ForeignKey(
        'venue.venue_id'), nullable=False)
    bookings = db.relationship('Booking', backref='show', lazy=True)

    def __repr__(self):
        return f'<Show {self.name}>'


class Booking(db.Model):
    __tablename__ = "booking"
    booking_id = db.Column(db.Integer, autoincrement=True, primary_key=True)
    show_id = db.Column(db.Integer, db.ForeignKey(
        'show.show_id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey(
        'user.user_id'), nullable=False)
    seats = db.Column(db.Integer, nullable=False)

    def __repr__(self):
        return f'<Booking {self.booking_id}>'

# __________________________________ROUTES_______________________


@app.route('/')
def home():
    if request.method == "GET":
        if current_user.is_authenticated:
            if current_user.is_admin:
                return redirect(url_for('admin_dashboard'))
            else:
                return redirect(url_for('user_dashboard'))
        return render_template('home.html')

# __________________________________SIGNUP_______________________


@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if current_user.is_authenticated:
        return redirect(url_for('home'))

    form = SignupForm()
    if form.validate_on_submit():
        name = form.name.data
        email = form.email.data
        password = form.password.data
        confirm = form.confirm.data

        user = User.query.filter_by(email=email).first()
        if user:
            flash('Email address already exists')
            return redirect(url_for('signup'))

        if password != confirm:
            flash('Passwords do not match')
            return redirect(url_for('signup'))

        hashed_password = generate_password_hash(password)

        new_user = User(name=name, email=email,
                        password_hash=hashed_password, is_admin=False)
        db.session.add(new_user)
        db.session.commit()
        flash('You have successfully signed up! You may now login.', 'success')
        return redirect(url_for('home'))

    return render_template('signup.html', form=form)

# __________________________________USER_LOGIN_______________________


@app.route('/user/login', methods=['GET', 'POST'])
def user_login():

    if current_user.is_authenticated:
        if current_user.is_admin:
            return redirect(url_for('admin_dashboard'))
        else:
            return redirect(url_for('user_dashboard'))

    form = LoginForm()

    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()

        if user is None or not user.verify_password(form.password.data):
            flash('Invalid email or password')
            return redirect(url_for('user_login'))

        if user.is_admin:
            flash('You are an admin')
            return redirect(url_for('admin_login'))

        login_user(user)
        if user.is_admin:
            return redirect(url_for('admin_dashboard'))
        else:
            return redirect(url_for('user_dashboard'))

    return render_template('user_login.html', title='User Login', form=form)

# __________________________________ADMIN_LOGIN_______________________


@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():

    if current_user.is_authenticated:
        if current_user.is_admin:
            return redirect(url_for('admin_dashboard'))
        else:
            return redirect(url_for('user_dashboard'))

    form = LoginForm()

    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()

        if user is None or not user.verify_password(form.password.data):
            flash('Invalid email or password')
            return redirect(url_for('admin_login'))

        if not user.is_admin:
            flash('You are not an admin')
            return redirect(url_for('user_login'))

        login_user(user)
        if user.is_admin:
            return redirect(url_for('admin_dashboard'))
        else:
            return redirect(url_for('user_dashboard'))

    return render_template('admin_login.html', title='Admin Login', form=form)

# __________________________________LOGOUT_______________________


@app.route('/logout')
@login_required
def logout():
    session.clear()
    logout_user()
    flash('You have been logged out.')
    return redirect(url_for('home'))

# __________________________________ADMIN_DASHBOARD_______________________


@app.route('/admin/dashboard')
@login_required
def admin_dashboard():
    if not current_user.is_admin:
        return redirect(url_for('user_dashboard'))

    venues = Venue.query.order_by(Venue.venue_id.asc()).all()
    shows = Show.query.order_by(Show.venue_id.asc()).all()

    return render_template('admin_dashboard.html', venues=venues, shows=shows)

# __________________________________USER_DASHBOARD_______________________


@app.route('/user/dashboard')
@login_required
def user_dashboard():
    if current_user.is_admin:
        return redirect(url_for('admin_dashboard'))

    venues = Venue.query.order_by(Venue.venue_id.asc()).limit(6).all()
    shows = Show.query.order_by(Show.venue_id.asc()).limit(6).all()

    return render_template('user_dashboard.html', venues=venues, shows=shows)

# __________________________________VENUE_CREATE_______________________


@app.route('/venues/create', methods=['GET', 'POST'])
@login_required
def create_venue():
    if not current_user.is_admin:
        return redirect(url_for('home'))

    form = VenueForm()

    if form.validate_on_submit():
        try:
            temp = Venue.query.filter_by(name=form.name.data).first()
            if temp:
                flash('Venue already exists')
                return redirect(url_for('create_venue'))
            venue = Venue(name=form.name.data, place=form.place.data,
                          capacity=form.capacity.data)
            db.session.add(venue)
            db.session.commit()
            flash('Venue created successfully')
            return redirect(url_for('admin_dashboard'))
        except Exception as e:
            db.session.rollback()
            flash(f'An error occurred while creating the venue: {str(e)}')
            return redirect(url_for('create_venue'))

    return render_template('create_venue.html', form=form)

# __________________________________VENUE_EDIT_______________________


@app.route('/venues/<int:id>/edit', methods=['GET', 'POST'])
@login_required
def edit_venue(id):
    if not current_user.is_admin:
        return redirect(url_for('home'))

    venue = Venue.query.get(id)
    form = VenueForm(obj=venue)

    if form.validate_on_submit():
        try:
            venue.name = form.name.data
            venue.place = form.place.data
            venue.capacity = form.capacity.data
            db.session.commit()
            flash('Venue updated successfully')
            return redirect(url_for('admin_dashboard'))
        except Exception as e:
            db.session.rollback()
            flash(f'An error occurred while updating the venue: {str(e)}')
            return redirect(url_for('edit_venue', id=id))

    return render_template('edit_venue.html', form=form, venue=venue)

# __________________________________VENUE_DELETE_______________________


@app.route('/venues/<int:id>/delete', methods=['GET', 'POST'])
@login_required
def delete_venue(id):
    venue = Venue.query.get_or_404(id)
    if not current_user.is_admin:
        flash('You do not have the necessary permissions to delete this venue.')
        return redirect(url_for('home'))

    form = DeleteForm()

    if form.validate_on_submit():
        shows = Show.query.filter_by(venue_id=id).all()
        for show in shows:
            bookings = Booking.query.filter_by(show_id=show.show_id).all()
            for booking in bookings:
                db.session.delete(booking)
            db.session.delete(show)
        db.session.delete(venue)
        db.session.commit()
        flash('Venue deleted successfully')
        return redirect(url_for('admin_dashboard'))

    return render_template('delete_venue.html', title='Delete Venue', venue=venue, form=form)

# __________________________________SHOW_CREATE_______________________


@app.route('/shows/create', methods=['GET', 'POST'])
@login_required
def create_show():
    if not current_user.is_admin:
        return redirect(url_for('home'))

    venue_id = request.args.get('venue_id')
    venue = Venue.query.get(venue_id)

    form = ShowForm(venue_id=venue_id)

    if form.validate_on_submit():
        temp = Show.query.filter_by(name=form.name.data).first()
        if temp:
            flash('Show already exists')
            return redirect(url_for('create_show', venue_id=venue_id))
        if form.ticket_price.data < 0:
            flash('Ticket price cannot be negative')
            return redirect(url_for('create_show', venue_id=venue_id))
        try:
            show = Show(name=form.name.data, rating=form.rating.data, tags=form.tags.data,
                        ticket_price=form.ticket_price.data, venue=venue)
            db.session.add(show)
            db.session.commit()
            flash('Show created successfully')
            return redirect(url_for('admin_dashboard'))
        except:
            db.session.rollback()
            flash('An error occurred while creating the show')
            return redirect(url_for('create_show', venue_id=venue_id))

    return render_template('create_show.html', form=form, venue=venue)

# __________________________________SHOW_EDIT_______________________


@app.route('/shows/<int:id>/edit', methods=['GET', 'POST'])
@login_required
def edit_show(id):
    if not current_user.is_admin:
        return redirect(url_for('home'))

    show = Show.query.get(id)
    form = ShowForm(obj=show)

    if form.validate_on_submit():
        form.populate_obj(show)
        db.session.commit()
        flash('Show updated successfully')
        return redirect(url_for('home'))
    return render_template('edit_show.html', form=form, show=show)

# __________________________________SHOW_DELETE_______________________


@app.route('/shows/<int:id>/delete', methods=['GET', 'POST'])
@login_required
def delete_show(id):
    show = Show.query.get_or_404(id)
    if not current_user.is_admin:
        flash('You do not have the necessary permissions to delete this show.')
        return redirect(url_for('home'))

    form = DeleteForm()

    if form.validate_on_submit():
        bookings = Booking.query.filter_by(show_id=id).all()
        for booking in bookings:
            db.session.delete(booking)
        db.session.delete(show)
        db.session.commit()
        flash('Show deleted successfully')
        return redirect(url_for('admin_dashboard'))

    return render_template('delete_show.html', title='Delete Show', show=show, form=form)

# __________________________________MY_BOOKINGS_______________________


@app.route('/bookings', methods=['GET'])
@login_required
def bookings():
    bookings = Booking.query.filter_by(user_id=current_user.user_id).all()
    return render_template('bookings.html', bookings=bookings)

# __________________________________BOOK_SHOW_______________________


@app.route('/booking/<int:id>', methods=['GET', 'POST'])
@login_required
def book_show(id):

    show = Show.query.get(id)
    venue = Venue.query.get(show.venue_id)

    if request.method == 'POST':
        seats = int(request.form['seats'])

        if seats > venue.capacity:
            flash('Selected seats exceed the capacity of the venue')
            return redirect(url_for('book_show', id=id))

        if seats > (venue.capacity - venue.seats_booked):
            flash('Selected seats are not available')
            return redirect(url_for('book_show', id=id))

        booking = Booking(
            show_id=show.show_id, user_id=current_user.user_id, seats=seats)
        try:
            db.session.add(booking)
            venue.seats_booked += seats
            db.session.commit()
            flash('Booking confirmed successfully')
        except:
            db.session.rollback()
            flash('An error occurred. Please try again later.')

        return redirect(url_for('book_show', id=id))

    return render_template('book.html', show=show, venue=venue)

# __________________________________CANCEL_BOOKING_______________________


@app.route('/bookings/<int:id>/cancel', methods=['GET', 'POST'])
@login_required
def cancel_booking(id):
    booking = Booking.query.get_or_404(id)

    form = DeleteForm()

    if form.validate_on_submit():
        try:
            booking.show.venue.seats_booked -= booking.seats
            db.session.delete(booking)
            db.session.commit()
            flash("Your booking has been cancelled.")
            return redirect(url_for('bookings'))
        except Exception as e:
            db.session.rollback()
            flash("An error occurred while cancelling your booking.")
            app.logger.error(str(e))

    return render_template('cancel_booking.html', title='Cancel Booking', booking=booking, form=form)

# __________________________________SEARCH_______________________


@app.route('/search', methods=['GET', 'POST'])
def search():
    form = SearchForm()
    if form.validate_on_submit():
        search_term = form.search.data.lower()
        if form.search_by.data == 'show':
            shows = Show.query.filter(Show.name.ilike(f'%{search_term}%') | Show.tags.ilike(
                f'%{search_term}%') | Show.rating.ilike(f'%{search_term}%')).all()
            return render_template('search_results.html', shows=shows)
        elif form.search_by.data == 'venue':
            venues = Venue.query.filter(Venue.name.ilike(
                f'%{search_term}%') | Venue.place.ilike(f'%{search_term}%')).all()
            return render_template('search_results.html', venues=venues)
    return render_template('search.html', form=form)

# __________________________________MAIN_______________________


if __name__ == "__main__":
    db.create_all()
    user = User.query.filter_by(email='admin@admin.com').first()
    if not user:
        admin = User(name='Admin', email='admin@admin.com',
                     password_hash=generate_password_hash('adminpwd'), is_admin=True)
        db.session.add(admin)
        db.session.commit()
    app.run(host='0.0.0.0', debug=True, port=5000)
