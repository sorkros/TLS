from flask import Flask, request,redirect,render_template,session,url_for,make_response,jsonify
import sys,ssl,logging
from util import tool,aes128

app = Flask(__name__)

ctx = ssl.create_default_context()

@app.route('/')
def Index():
    tool.refresh_tls(ctx)
    return render_template("index.html")

@app.route('/version-control',methods=['POST','GET'])
def version_control() :
    try :
        if request.method == 'POST' :
            vers = request.form.getlist('version')
            tmp = ['0','1','2','3']
            res = list(set(tmp) - set(vers))
            tool.print_data(ctx)
            
            if res == [] :
                pass
            else :
                for i in res :
                    tool.removing_tls(ctx,int(i))
            tool.print_data(ctx)
            return render_template("test.html")
    except Exception as e :
        logging.warning(e)

@app.route('/request' , methods=["POST","GET"])
def request_post() :
    try :
        if request.method == 'POST' :
            id = request.form['id']
            pwd = request.form['pwd']

            assert id is not None
            assert pwd is not None

            enc_data = aes128.AES128(bytes(aes128.key)).encrypt(id+pwd)
            hexList = list()
            for b in bytearray(enc_data) :
                hexList.append(hex(b))

            resp = make_response(render_template('get.html'))
            resp.set_cookie('auth', enc_data)
            print(hexList)

            return resp

    except Exception as e :
        logging.warning(e)

@app.route('/request/get_token',methods=['GET'])
def get_token() :
    auth = request.cookies.get('auth')

    dec_data = aes128.AES128(bytes(aes128.key)).decrypt(auth)
    return jsonify(DECODE = dec_data.decode('utf-8')),200

if __name__=='__main__':
    print("Python {:s} on {:s}\n".format(sys.version, sys.platform))
    tool.print_data(ctx)
    tool.log()
    app.run()
