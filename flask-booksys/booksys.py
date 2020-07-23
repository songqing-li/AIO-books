from flask import (
	Blueprint, flash, g, redirect, render_template, request, url_for
)
from werkzeug.exceptions import abort

from flaskr.auth import login_required
from flaskr.db import get_db
from flaskr.aes import get_random_key_readable, aes_cbc_encrypt, aes_cbc_decrypt
from flaskr.makeqrcode import makeQrCode
from flaskr.encrsa import RSAUtil
import os
import base64

img_save_path = 'D:\\Diploma_project\\flask-tutorial\\flaskr\\static\\image\\{}.png'

bp = Blueprint('booksys', __name__)

@bp.route('/search', methods=('GET', 'POST'))
def search():
    if request.method == 'POST':
        str_miwen = request.form['str_miwen'] #print('str_miwen:', str_miwen, 'type:', type(str_miwen))

        error = None

        if not str_miwen:
            error = '请输入加密二维码内容'
        if error is not None:
            flash(error)
        else:
            book = get_db().execute(
				'SELECT mingwen, str_miwen, miwen, key, enctype'
				' FROM book b WHERE b.str_miwen = ?',
				(str_miwen,)
			).fetchone()

            res = None
            if book is None:
                res = "下列图书未找到:{}".format(str_miwen)
            else:
                enctype = book['enctype']
                if enctype == "AES":
                    res = aes_cbc_decrypt(book['miwen'], book['key'])
                    res = str(res, encoding="utf-8")
                elif enctype == "RSA":
                    rsaUtil = RSAUtil()
                    res = rsaUtil.decrypt_by_private_key(book['miwen'])
                    res = str(res, encoding='utf-8')
                elif enctype == "无":
                    res = book['miwen']
                else:
                    res = "下列图书未找到:{}".format(str_miwen)

            return render_template('booksys/result.html', res=res)

    return render_template('booksys/search.html')

@bp.route('/')
@login_required
def index():
    db = get_db()
    books = db.execute(
        'SELECT b.id, mingwen, str_miwen, miwen, created, author_id, enctype, username'
        ' FROM book b JOIN user u ON b.author_id = u.id'
        ' ORDER BY created DESC'
    ).fetchall()
    return render_template('booksys/index.html', books=books)


@bp.route('/create', methods=('GET', 'POST'))
@login_required
def create():
    if request.method == 'POST':
        mingwen = request.form['mingwen']
        enctype = request.form['enctype']

        key, miwen, is_decode = b'None', None, 1
        if enctype == "AES":
        	key = get_random_key_readable()
        	miwen = aes_cbc_encrypt(mingwen, key)
        elif enctype == "RSA":
        	rsaUtil = RSAUtil()
        	miwen = rsaUtil.encrypt_by_public_key(bytes(mingwen, encoding='utf-8'))
        elif enctype == "无":
            miwen = mingwen
            is_decode = 0

        str_miwen = miwen.decode("utf-8", errors='ignore') if is_decode else miwen

        str_miwen = str_miwen.replace('\n', '').replace('\r', '').strip()
        error = None

        if not mingwen:
            error = '请输入明文'

        if error is not None:
            flash(error)
        else:
            db = get_db()
            db.execute(
                'INSERT INTO book (mingwen, str_miwen, miwen, author_id, key, enctype)'
                ' VALUES (?, ?, ?, ?, ?, ?)',
                (mingwen, str_miwen, miwen, g.user['id'], key, enctype)
            )
            db.commit()

            bookid = get_db().execute(
            	'SELECT b.id, mingwen, author_id, key'
            	' FROM book b JOIN user u ON b.author_id = u.id'
            	' WHERE mingwen = ?', 
            	(mingwen,)
            ).fetchone()

            #qrcode
            codeData = str_miwen.strip()
            global img_save_path
            cur_path = img_save_path.format(bookid['id'])
            makeQrCode(codeData, cur_path)
            '''
            print('mingwen:', bookid['mingwen'], 'type:', type(bookid['mingwen']))
            print('str_miwen:', str_miwen, 'type:', type(str_miwen))
            print('miwen:', miwen, 'type:', type(miwen))
            print('key:', bookid['key'], 'type:', type(bookid['key']))
            '''


            return redirect(url_for('booksys.index'))

    return render_template('booksys/create.html')

def get_book(id, check_author=True):
    book = get_db().execute(
        'SELECT b.id, mingwen, str_miwen, miwen, created, author_id, username'
        ' FROM book b JOIN user u ON b.author_id = u.id'
        ' WHERE b.id = ?',
        (id,)
    ).fetchone()

    if book is None:
        abort(404, "图书 id {0} 不存在".format(id))

    if check_author and book['author_id'] != g.user['id']:
        abort(403)

    return book

@bp.route('/<int:id>/update', methods=('GET', 'POST'))
@login_required
def update(id):
    book = get_book(id)

    if request.method == 'POST':
        mingwen = request.form['mingwen']
        enctype = request.form['enctype']

        key, miwen, is_decode = b'None', None, 1
        if enctype == "AES":
        	key = get_random_key_readable()
        	miwen = aes_cbc_encrypt(mingwen, key)
        elif enctype == "RSA":
        	rsaUtil = RSAUtil()
        	miwen = rsaUtil.encrypt_by_public_key(bytes(mingwen, encoding='utf-8'))
        elif enctype == "无":
            miwen = mingwen
            is_decode = 0

        str_miwen = miwen.decode('utf-8', errors='ignore') if is_decode else miwen

        str_miwen = str_miwen.replace('\n', '').replace('\r', '').strip()
        error = None

        if not mingwen:
            error = '请输入明文'

        if error is not None:
            flash(error)
        else:
            db = get_db()
            db.execute(
                'UPDATE book SET mingwen = ?, str_miwen = ?, miwen = ?, key = ?, enctype = ?'
                ' WHERE id = ?',
                (mingwen, str_miwen, miwen, key, enctype, id)
            )
            db.commit()

            #qrcode
            codeData = str_miwen.strip()
            global img_save_path
            cur_path = img_save_path.format(id)
            makeQrCode(codeData, cur_path)

            return redirect(url_for('booksys.index'))

    return render_template('booksys/update.html', book=book)

@bp.route('/<int:id>/delete', methods=('POST',))
@login_required
def delete(id):
    get_book(id)
    db = get_db()
    db.execute('DELETE FROM book WHERE id = ?', (id,))
    db.commit()

    #qrcode
    global img_save_path
    cur_path = img_save_path.format(id)
    os.remove(cur_path)

    return redirect(url_for('booksys.index'))