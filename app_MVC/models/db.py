from flask_mysqldb import MySQL
import MySQLdb.cursors

class db:
	def __init__(self,app):
		

		app.config['MYSQL_HOST'] = 'localhost'
		app.config['MYSQL_USER'] = 'user'
		app.config['MYSQL_PASSWORD'] = 'user'
		app.config['MYSQL_DB'] = 'app'


		

		self.mysql=MySQL(app)

	'''
	def conf(self,app):
		# Enter your database connection details below
		app.config['MYSQL_HOST'] = 'localhost'
		app.config['MYSQL_USER'] = 'user'
		app.config['MYSQL_PASSWORD'] = 'userUSER@123'
		app.config['MYSQL_DB'] = 'app'
	'''

	#Check if the username and the password are correct 
	def valide_user(self,username,password):
		cursor = self.mysql.connection.cursor(MySQLdb.cursors.DictCursor)
		cursor.execute('SELECT * FROM accounts WHERE username = %s AND password = %s', (username, password))
        # Fetch one record and return result
		account = cursor.fetchone()
		return(account) #This method retrieves the next row of a query result set and returns a single sequence, or None if no more rows are available

	#Add a user to our data base
	def add_user(self,username,password,email):
		cursor = self.mysql.connection.cursor(MySQLdb.cursors.DictCursor)
		cursor.execute('INSERT INTO accounts VALUES (NULL, %s, %s, %s)', (username, password, email))
		self.mysql.connection.commit()


		#Add a request to the database
	def add_request(self,id_user,ip_source, user_agent,date,site):
		cursor = self.mysql.connection.cursor(MySQLdb.cursors.DictCursor)
		cursor.execute('INSERT INTO requests VALUES(NULL , %s , %s ,%s ,%s,%s)' ,(id_user,ip_source, user_agent,date,site))
		self.mysql.connection.commit()


	def get_requests(self,identifiant):
		cursor = self.mysql.connection.cursor(MySQLdb.cursors.DictCursor)
		cursor.execute('SELECT * FROM requests WHERE id_user=%d' %(identifiant))
		requests = cursor.fetchall()
		return(requests)


	def exist_user(self,username):
		cursor = self.mysql.connection.cursor(MySQLdb.cursors.DictCursor)
		cursor.execute('SELECT * FROM accounts WHERE username = %s', [username])
		account = cursor.fetchone()
		return(account)






