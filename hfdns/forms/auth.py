
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField, SubmitField
from werkzeug.security import generate_password_hash, check_password_hash
from wtforms.validators import Required, Length, Email, Regexp, EqualTo
from wtforms import ValidationError
from ..models import User


class LoginForm(FlaskForm):
    username = StringField('JIRA账号', validators=[Required(), Length(1, 64)])
    password = PasswordField('JIRA账号', validators=[Required()])
    remember_me = BooleanField('记住我')
    submit = SubmitField('登 录')


class RegistrationForm(FlaskForm):
    username = StringField('请输入用户名', validators=[
        Required(), Length(1, 64), Regexp('^[A-Za-z][A-Za-z0-9_.]*$', 0,
                                          'Usernames must have only letters, '
                                          'numbers, dots or underscores')])
    email = StringField('邮箱', validators=[Required(), Length(1, 64),
                                           Email()])
    password = PasswordField('请输入密码', validators=[
        Required(), EqualTo('password2', message='两次密码必须相同！')])
    password2 = PasswordField('请重复密码', validators=[Required()])
    submit = SubmitField('注 册')

    def validate_email(self, field):
        if User.query.filter_by(email=field.data).first():
            raise ValidationError('此邮箱已存在')

    def validate_username(self, field):
        if User.query.filter_by(username=field.data).first():
            raise ValidationError('此用户已存在')

