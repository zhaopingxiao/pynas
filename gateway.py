import flask, threading, api
app = flask.Flask(__name__)

lock = threading.Lock()

api.init_db()

@app.route('/')
def index():
    return flask.redirect('/home')

@app.route('/background')
def background():
    return flask.send_from_directory('static', 'background.png')

@app.route('/home')
def home():
    token = flask.request.cookies.get('token')
    if token:
        if api.have_token(token, lock):
            if api.is_admin(token, lock):
                return flask.render_template('home.html', is_admin=True)
            return flask.render_template('home.html', is_admin=False)
        else:
            response = flask.make_response(flask.render_template('login.html', error='登录过期'))
            response.delete_cookie('token')
            return response
    else:
        return flask.redirect('/login')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if flask.request.method == 'GET':
        return flask.render_template('login.html')
    else:
        username = flask.request.form.get('username')
        password = flask.request.form.get('password')
        token = api.login(username, password, lock)
        if token:
            response = flask.make_response(flask.redirect('/home'))
            response.set_cookie('token', token, max_age=60*60*24*7)
            return response
        else:
            return flask.render_template('login.html', error='账号或密码错误')

@app.route('/un_login')
def un_login():
    token = flask.request.cookies.get('token')
    if token:
        api.logout(token, lock)
    response = flask.make_response(flask.redirect('/home'))
    response.delete_cookie('token')
    return response

@app.route('/users_setting', methods=['GET', 'POST'])
def users_setting():
    token = flask.request.cookies.get('token')
    if not api.have_token(token, lock):
        response = flask.make_response(flask.redirect('/login'))
        response.delete_cookie('token')
        return response
    
    if not api.is_admin(token, lock):
        return flask.redirect('/home')
    
    if flask.request.method == 'POST':
        action = flask.request.form.get('action')
        messages = []
        
        if action == 'add':
            new_username = flask.request.form.get('username')
            new_password = flask.request.form.get('password')
            role = flask.request.form.get('role', 'user')
            
            try:
                api.add_user(new_username, new_password, role, lock)
                messages.append(('success', '用户添加成功'))
            except Exception as e:
                messages.append(('error', f'添加用户失败: {str(e)}'))
        
        elif action == 'delete':
            delete_username = flask.request.form.get('username')
            
            try:
                api.delete_user(delete_username, lock)
            except Exception as e:
                messages.append(('error', f'删除用户失败: {str(e)}'))
        
        elif action == 'change_password':
            change_username = flask.request.form.get('username')
            new_password = flask.request.form.get('new_password')
            
            try:
                api.change_password(change_username, new_password, lock)
                messages.append(('success', '密码修改成功'))
            except Exception as e:
                messages.append(('error', f'修改密码失败: {str(e)}'))
        
        users = api.get_users(lock)
        
        admin_count = api.admin_count(lock)
        
        return flask.render_template('user_set.html', users=users, admin_count=admin_count, messages=messages)
    
    else:
        users = api.get_users(lock)
        
        admin_count = api.admin_count(lock)
        
        return flask.render_template('user_set.html', users=users, admin_count=admin_count, messages=[])

if __name__ == '__main__':
    threading.Thread(target=api.token_close, args=(lock,)).start()
    app.run(host='0.0.0.0', port=5680)