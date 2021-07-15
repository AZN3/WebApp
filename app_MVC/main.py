from flask import Flask, render_template, request, redirect, url_for, session
#from flask_mysqldb import MySQL
#import MySQLdb.cursors
from datetime import datetime
import re
#from ipwhois import IPWhois 
#import dns.resolver
from flask_bootstrap import Bootstrap
from models import domain , dnsLU , RDAP , shodanLU, db
app = Flask(__name__)

app.secret_key = '1a2b3c4d5e'


database=db.db(app)

#===============================================
# Enter your database connection details below
#app.config['MYSQL_HOST'] = 'localhost'
#app.config['MYSQL_USER'] = 'user'
#app.config['MYSQL_PASSWORD'] = 'userUSER@123'
#app.config['MYSQL_DB'] = 'app'

# Intialize MySQL
#mysql = MySQL(app)
#==============================================



# http://localhost:5000/ - this will be the login page, we need to use both GET and POST requests
@app.route('/', methods=['GET', 'POST'])
def login():
# Output message if something goes wrong...
    msg = ''
    # Check if "username" and "password" POST requests exist (user submitted form)
    if request.method == 'POST' and 'username' in request.form and 'password' in request.form:
        # Create variables for easy access
        username = request.form['username']
        password = request.form['password']



        #A commenter!!!!!
        #===============================================================
        # Check if account exists using MySQL
        #cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        
        #cursor.execute('SELECT * FROM accounts WHERE username = %s AND password = %s', (username, password))
        # Fetch one record and return result
        #account = cursor.fetchone()
        #===============================================================

        account=database.valide_user(username,password)


                # If account exists in accounts table in out database
        if account:
            # Create session data, we can access this data in other routes
            session['loggedin'] = True
            session['id'] = account['id']
            session['username'] = account['username']
            session['password'] = account['password']
            session['email'] = account['email']

            # Redirect to home page

            return redirect(url_for('home'))
        else:
            # Account doesnt exist or username/password incorrect
            msg = 'Incorrect username/password!'
    return render_template('login.html', msg=msg)



# http://localhost:5000/pythinlogin/register - this will be the registration page, we need to use both GET and POST requests
@app.route('/register/', methods=['GET', 'POST'])
def register():
    # Output message if something goes wrong...
    msg = ''
    # Check if "username", "password" and "email" POST requests exist (user submitted form)
    if request.method == 'POST' and 'username' in request.form and 'password' in request.form and 'email' in request.form:
        # Create variables for easy access
        username = request.form['username']
        password = request.form['password']
        email = request.form['email']
                # Check if account exists using MySQL

                #A commenter!!!!!!! db.valide_user()
        #===========================================================================
        #cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        
        #cursor.execute('SELECT * FROM accounts WHERE username = %s', [username])
        #account = cursor.fetchone()
        #!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
        #===========================================================================
        account = database.exist_user(username)




        # If account exists show error and validation checks
        if account:
            msg = 'Account already exists!'
        elif not re.match(r'[^@]+@[^@]+\.[^@]+', email):
            msg = 'Invalid email address!'
        elif not re.match(r'[A-Za-z0-9]+', username):
            msg = 'Username must contain only characters and numbers!'
        elif not username or not password or not email:
            msg = 'Please fill out the form!'
        else:
            # Account doesnt exists and the form data is valid, now insert new account into accounts table
            

            #===========================================================================
            #!!! db.add_user()
            #cursor.execute('INSERT INTO accounts VALUES (NULL, %s, %s, %s)', (username, password, email))
            #mysql.connection.commit()
            #!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!1
            #===========================================================================


            database.add_user(username, password, email)


            msg = 'You have successfully registered!'
    elif request.method == 'POST':
        # Form is empty... (no POST data)
        msg = 'Please fill out the form!'
    # Show registration form with message (if any)
    return render_template('signup.html', msg=msg)

# http://localhost:5000/pythinlogin/home - this will be the home page, only accessible for loggedin users
@app.route('/home')
def home():
    # Check if user is loggedin
    if 'loggedin' in session:
        # User is loggedin show them the home page
        return render_template('home.html',msg='')
    # User is not loggedin redirect to login page
    return redirect(url_for('login'))   



@app.route('/search', methods=['GET', 'POST'])
def search():
    if request.method == "POST":

                
        url=request.form['search']

        url=domain.domain(url)
        if url.dnsRec.valid:


            A=url.dnsRec.get_A()
            A=[val.to_text() for val in A]
            


            NS=url.dnsRec.get_NS()
            MX=url.dnsRec.get_MX()
            if url.dnsRec.site :
                NS=['-']
                MX=['- -']
                subdomains=['-']
            else :
                NS=[val.to_text() for val in NS]
                MX=[ val.to_text() for val in MX]
                
                subdomains=url.get_subdomains()

            MX=[val.split() for val in MX]    

            rdap=url.rdapRec.get_rdap()
            
            query = rdap[0]['query']

            asn=[list(val.keys())[0] for val in rdap[1:7]]
            
            
            
            
            
            asn_val=[list(val.values())[0] for val in rdap[1:7] ]

            entities=rdap[7]['entities']


            network=rdap[8]['network']
            net=[list(val.keys())[0] for val in network]
            net_val=[list(val.values())[0] for val in network]
            

            objects=rdap[9]['objects']
            contact=[item[2]['contact'] for item in objects]


            shodan,v=url.shodRec.get_shod()
            shodan_keys=[list(item.keys()) for item in shodan if list(item.keys())[0] != 'vulns' ]
            shodan_values=[list(item.values()) for item in shodan if list(item.keys())[0] != 'vulns']      
            vulns=[list(item.values()) for item in shodan if list(item.keys())[0] == 'vulns'] 
            
            
            #récupération des requettes lancées par un utilisateur
            id_user=session['id']
            
            ip_source=request.remote_addr
            
            
            user_agent=request.headers.get('User-Agent').split()
            user_agent=user_agent[0]
            date= datetime.now()
            date=str(date).split()
            date=date[0]
            
            
            site= request.form['search']


            #===========================================================================
            #cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
            #cursor.execute('INSERT INTO requests VALUES(NULL , %s , %s ,%s ,%s,%s)' ,(id_user,ip_source, user_agent,date,site))
            #mysql.connection.commit()
            #===========================================================================
            
            database.add_request(id_user,ip_source, user_agent,date,site)

        else:
            return render_template('home.html',msg='Nom de Domaine Invalide!!!')
     
    return render_template('index.html'  ,A=A , NS=NS, MX=MX ,asn=asn , asn_val=asn_val,net=net,net_val=net_val , subdomain=subdomains,entities=entities,query=query , obj=objects , contact=contact ,shodan_keys=shodan_keys,shodan_values=shodan_values,vulns=vulns)



@app.route('/profile')
def profile():
    # Check if user is loggedin
    if 'loggedin' in session:
        identifiant=session['id'] 

        #==============================================================
        #cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        #cursor.execute('SELECT * FROM requests WHERE id_user=%d' %(identifiant))
        #requests = cursor.fetchall()
        #===============================================================


        requests=database.get_requests(identifiant)
         
        # User is loggedin show them the home page
        return render_template('profile.html' , username=session['username']
        , email=session['email'],requests=requests)
    # User is not loggedin redirect to login page
    return redirect(url_for('login')) 


@app.route('/logout')

def logout():
    session.pop('username',None)
    return redirect(url_for('login'))



if __name__ =='__main__':
	app.run(Debug=True)
