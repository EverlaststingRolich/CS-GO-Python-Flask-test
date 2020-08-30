from flask import Flask, render_template, url_for, request, redirect, flash
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
from flask_login import UserMixin, LoginManager
from werkzeug.security import check_password_hash, generate_password_hash
from flask_login import login_user, login_required, logout_user
#from flask_security import RoleMixin


app = Flask(__name__)
app.secret_key = 'secret key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgres://postgres:SS7767102@localhost/posts'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)
manager = LoginManager(app)


class Article(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    intro = db.Column(db.String(300), nullable=False)
    text = db.Column(db.Text, nullable=False)
    date = db.Column(db.DateTime, default=datetime.utcnow)

    def __repr__(self):
        return '<Article %r>' % self.id


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    login = db.Column(db.String(128), nullable=False, unique=True)
    password = db.Column(db.String(255), nullable=False)

    def __repr__(self):
        return '<User %r>' % self.id


#class Role(db.Model, RoleMixin):
 #   id = db.Column(db.Integer(), primary_key=True)
   # name = db.Column(db.String(80), unique=True)
   # description = db.Column(db.String(255))

   # def __repr__(self):
   #     return '<Role %r>' % self.id



@manager.user_loader
def load_user(user_id):
    return User.query.get(user_id)


db.create_all()


@app.route('/login', methods=['POST', 'GET'])
def login_page():
    login = request.form.get('login')
    password = request.form.get('password')

    if login and password:
        user = User.query.filter_by(login=login).first()

        if user and check_password_hash(user.password, password):
            login_user(user)

            next_page = request.args.get('next')

            if next_page:
                return redirect(next_page)

            else:
                return render_template('index.html')
        else:
            flash('Неправильный логин или пароль')
            return render_template('login.html')
    else:
        flash('Введите логин и пароль')
        return render_template('login.html')


@app.route('/register', methods=['POST', 'GET'])
def register():
    login = request.form.get('login')
    password = request.form.get('password')
    password2 = request.form.get('password2')

    if request.method == 'POST':
        if not (login or password or password2):
            flash('Заполните все поля')
        elif password != password2:
            flash('Введённые пароли различаются')
        else:
            hash_pwd = generate_password_hash(password)
            new_user = User(login=login, password=hash_pwd)
            db.session.add(new_user)
            db.session.commit()

            return redirect(url_for('login_page'))
    return render_template('register.html')


@app.route('/logout', methods=['POST', 'GET'])
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))


@app.after_request
def redirect_to_signin(response):
    if response.status_code == 401:
        return redirect(url_for('login_page') + '?next=' + request.url)

    return response


@app.route('/')
@app.route('/home')
def index():
    return render_template("index.html")


@app.route('/maps')
def maps():
    return render_template("maps.html")


@app.route('/dust2')
def dust2():
    return render_template("dust2.html")


@app.route('/inferno')
def inferno():
    return render_template("inferno.html")


@app.route('/posts')
def posts():
    articles = Article.query.order_by(Article.date.desc()).all()
    return render_template("posts.html", articles=articles)


@app.route('/adm_test')
def adm_test():
    return render_template("adm_test.html")





@app.route('/create_post', methods=['POST', 'GET'])

def create_post():
    if request.method == 'POST':
        title = request.form['title']
        intro = request.form['intro']
        text = request.form['text']
        article = Article(title=title, intro=intro, text=text)

        try:
            db.session.add(article)
            db.session.commit()
            return redirect('/posts')
        except:
            return "При добавлении статьи произошла ошибка"

    else:
        return render_template("create_post.html")



@app.route('/<int:id>')
@login_required
def post_detail(id):
    article = Article.query.get(id)
    return render_template("post_detail.html", article=article)


@app.route('/posts/<int:id>/del')
@login_required
def post_delete(id):
    article = Article.query.get_or_404(id)

    try:
        db.session.delete(article)
        db.session.commit()
        return redirect('/posts')
    except:
        return "При удалении статьи произошла ошибка"



if (__name__ == "__main__"):
    app.run(debug=True)
