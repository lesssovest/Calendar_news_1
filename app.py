import os
from datetime import date, datetime
from functools import wraps
from flask import Flask, jsonify, render_template, request, redirect, url_for, session, flash
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash

app=Flask(__name__)
app.config["SECRET_KEY"]=os.getenv("SECRET_KEY","change-me")
dburl=os.getenv("DATABASE_URL","sqlite:///calendar.db")
if dburl.startswith("postgres://"): dburl=dburl.replace("postgres://","postgresql://",1)
if dburl.startswith("postgresql://") and "+psycopg" not in dburl: dburl=dburl.replace("postgresql://","postgresql+psycopg://",1)
app.config["SQLALCHEMY_DATABASE_URI"]=dburl
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"]=False
db=SQLAlchemy(app)

class Team(db.Model):
    id=db.Column(db.Integer,primary_key=True); name=db.Column(db.String(120),unique=True,nullable=False)
    color=db.Column(db.String(20),nullable=False,default="#B8D8FF")
class User(db.Model):
    id=db.Column(db.Integer,primary_key=True); email=db.Column(db.String(255),unique=True,nullable=False)
    name=db.Column(db.String(120),nullable=False); password_hash=db.Column(db.String(255),nullable=False)
    role=db.Column(db.String(20),nullable=False,default="member"); team_id=db.Column(db.Integer,db.ForeignKey("team.id"))
    team=db.relationship("Team",backref="users")
class Booking(db.Model):
    id=db.Column(db.Integer,primary_key=True); publish_date=db.Column(db.Date,unique=True,nullable=False)
    title=db.Column(db.String(255),nullable=False); important=db.Column(db.Boolean,default=False,nullable=False)
    team_id=db.Column(db.Integer,db.ForeignKey("team.id"),nullable=False); created_by=db.Column(db.Integer,nullable=False)
    team=db.relationship("Team",backref="bookings")
class AuditLog(db.Model):
    id=db.Column(db.Integer,primary_key=True); action=db.Column(db.String(30),nullable=False)
    booking_id=db.Column(db.Integer); publish_date=db.Column(db.Date); title=db.Column(db.String(255))
    team_name=db.Column(db.String(120)); actor_email=db.Column(db.String(255),nullable=False)
    created_at=db.Column(db.DateTime,default=datetime.utcnow,nullable=False)

def user():
    return db.session.get(User,session.get("user_id")) if session.get("user_id") else None
def login_required(f):
    @wraps(f)
    def w(*a,**k):
        if not user(): return redirect(url_for("login"))
        return f(*a,**k)
    return w
def allowed(d): return d.weekday()<5
def manages(b):
    u=user(); return u and (u.role=="admin" or u.team_id==b.team_id)

@app.context_processor
def ctx(): return {"user":user()}

@app.route("/health")
def health(): return {"status":"ok"}

@app.route("/login",methods=["GET","POST"])
def login():
    if request.method=="POST":
        u=User.query.filter_by(email=request.form.get("email","").strip().lower()).first()
        if u and check_password_hash(u.password_hash,request.form.get("password","")):
            session["user_id"]=u.id; return redirect(url_for("calendar"))
        flash("Неверный email или пароль","error")
    return render_template("login.html")

@app.route("/logout")
def logout(): session.clear(); return redirect(url_for("login"))

@app.route("/")
@login_required
def calendar(): return render_template("calendar.html",teams=Team.query.order_by(Team.name).all())

@app.route("/history")
@login_required
def history(): return render_template("history.html",logs=AuditLog.query.order_by(AuditLog.created_at.desc()).limit(300).all())

@app.route("/teams")
@login_required
def teams():
    if user().role!="admin": flash("Только администратор","error"); return redirect(url_for("calendar"))
    return render_template("teams.html",teams=Team.query.order_by(Team.name),users=User.query.order_by(User.email))

@app.get("/api/bookings")
@login_required
def get_bookings():
    q=Booking.query
    if request.args.get("start"): q=q.filter(Booking.publish_date>=date.fromisoformat(request.args["start"]))
    if request.args.get("end"): q=q.filter(Booking.publish_date<=date.fromisoformat(request.args["end"]))
    return jsonify([{"id":b.id,"date":b.publish_date.isoformat(),"title":b.title,"important":b.important,
        "team":b.team.name,"teamId":b.team_id,"color":b.team.color,"canManage":manages(b)} for b in q.order_by(Booking.publish_date)])

@app.post("/api/bookings")
@login_required
def create():
    u=user(); d=date.fromisoformat(request.json["date"])
    if not allowed(d): return {"error":"Суббота и воскресенье закрыты"},400
    if Booking.query.filter_by(publish_date=d).first(): return {"error":"На эту дату уже есть публикация"},409
    title=(request.json.get("title") or "").strip()
    if not title: return {"error":"Укажите название"},400
    tid=u.team_id if u.role!="admin" else request.json.get("teamId")
    if not tid: return {"error":"Выберите команду"},400
    b=Booking(publish_date=d,title=title[:255],important=bool(request.json.get("important")),team_id=int(tid),created_by=u.id)
    db.session.add(b); db.session.flush()
    db.session.add(AuditLog(action="created",booking_id=b.id,publish_date=d,title=b.title,team_name=b.team.name,actor_email=u.email))
    db.session.commit(); return {"ok":True}

@app.put("/api/bookings/<int:bid>")
@login_required
def update(bid):
    b=db.session.get(Booking,bid)
    if not b: return {"error":"Не найдено"},404
    if not manages(b): return {"error":"Нет доступа"},403
    d=date.fromisoformat(request.json["date"])
    if not allowed(d): return {"error":"Суббота и воскресенье закрыты"},400
    if Booking.query.filter(Booking.publish_date==d,Booking.id!=b.id).first(): return {"error":"Новая дата уже занята"},409
    b.publish_date=d; b.title=(request.json.get("title") or "").strip()[:255]; b.important=bool(request.json.get("important"))
    db.session.add(AuditLog(action="updated",booking_id=b.id,publish_date=d,title=b.title,team_name=b.team.name,actor_email=user().email))
    db.session.commit(); return {"ok":True}

@app.delete("/api/bookings/<int:bid>")
@login_required
def delete(bid):
    b=db.session.get(Booking,bid)
    if not b: return {"error":"Не найдено"},404
    if not manages(b): return {"error":"Нет доступа"},403
    db.session.add(AuditLog(action="deleted",booking_id=b.id,publish_date=b.publish_date,title=b.title,team_name=b.team.name,actor_email=user().email))
    db.session.delete(b); db.session.commit(); return {"ok":True}

def seed():
    db.create_all()
    if Team.query.count()==0:
        for n,c in [("Platform","#B8D8FF"),("Frontend","#C8E6C9"),("Backend","#FFD7BA"),("Mobile","#D9C2FF"),("QA","#FFE4A3")]:
            db.session.add(Team(name=n,color=c))
        db.session.commit()
    if User.query.count()==0:
        ts=Team.query.all()
        admin_email=os.getenv("ADMIN_EMAIL")
        admin_password=os.getenv("ADMIN_PASSWORD")
        if admin_email and admin_password:
            db.session.add(User(email=admin_email.strip().lower(),name=os.getenv("ADMIN_NAME","Admin"),
                                password_hash=generate_password_hash(admin_password),role="admin",team_id=ts[0].id))
            db.session.commit()
with app.app_context(): seed()
if __name__=="__main__": app.run(host="0.0.0.0",port=int(os.getenv("PORT","8080")))
