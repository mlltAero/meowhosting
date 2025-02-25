import mysql.connector

def connectDb(host='localhost', user='root', password='', database='electo'):
    """
    Connects to the provided MySQL database.
    """
    return mysql.connector.connect(host=host, user=user, password=password, database=database)

def createCursor(cursor: mysql.connector.MySQLConnection):
    """
    Creates a MySQL cursor.
    """
    return cursor.cursor()