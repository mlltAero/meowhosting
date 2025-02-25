from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware

from meowLib.logd.logd import logd
from meowLib.keyManager import keyManager
from meowLib.sqlManager import sqlManager

import mysql.connector, random
from typing import Annotated
from pydantic import BaseModel, constr, EmailStr

logd('Checking for private key before starting API')

if not keyManager.checkForKey(file_name='rsa2048.pem'): 
    logd('Generating private key')
    keyManager.generateKey(file_name='rsa2048.pem')

logd('Loading key as privateKey')
privateKey = keyManager.loadPrivateKey(file_name='rsa2048.pem')  

api = FastAPI()

logd('Hello, world!')
logd('Setting CORS options')

api.add_middleware(
    CORSMiddleware,
    allow_origins=['*'],
    allow_credentials=True,
    allow_methods=['*'],
    allow_headers=['*'],
)

@api.get('/pubkey')                                             
async def pubkey():

    logd('Generating public key')

    publicKey = keyManager.getPublicKey(privateKey)             
    publicPEM = keyManager.serializePublicKey(publicKey)

    logd('Public key generated')

    return {'pubkey': publicPEM}                

class RegisterRequest(BaseModel):                               
    username    : Annotated[str, constr(min_length=3, max_length=30)]
    password    : Annotated[str, constr(min_length=8, max_length=32)]
    mail        : EmailStr

@api.post('/register')                                          # Register username, password and email to database
async def regform(data: RegisterRequest):

    # THIS IS FOR DEBUGGING ONLY. REMOVE IN PRODUCTION!
    logd('[DEV - REMOVE IN PROD] Registering with ' + data.username)

    try:
        database = sqlManager.connectDb()               # Uses defaults
        sqlCursor = sqlManager.createCursor(database)                           # Create MySQL database cursor

        cursorCode = 'INSERT INTO meowhosting.userdata (user, password, salt, is_admin, userID, mail, confirmationCode, is_activated) VALUES (%s, %s, %s, %s, %s, %s, %s, %s)'

        salt = keyManager.generateSalt(size=16)                         # Generate salt
        publicKey = keyManager.getPublicKey(privateKey)

        decryptedPass = keyManager.decrypt(data.password, privateKey)
        passwordForEncryption = str(salt) + decryptedPass.decode('utf-8')   # Salt the received password
        encryptedPass = keyManager.encrypt(passwordForEncryption, publicKey)

        confirmationCode = str(random.randint(100000, 999999))

        """ 

        emailConfig = mailController.loadEmailConfig()

        smtpServer = emailConfig['smtp_server']
        smtpPort = emailConfig['smtp_port']
        senderEmail = emailConfig['sender_email']
        senderPassword = emailConfig['sender_password']

        status = mailController.sendConfirmationEmail(
            smtp_server=smtpServer, 
            smtp_port=smtpPort, 
            sender_email=senderEmail, 
            sender_password=senderPassword, 
            recipient_email=data.mail, 
            confirmation_code=confirmationCode
        )

        """

        status = True       # TODO - make password resets and activation work
        devMode = True

        if status or devMode:
            sqlCursor.execute(cursorCode, 
                (
                    data.username,                  # Username
                    encryptedPass.hex(),            # Password
                    salt,                           # Salt
                    0,                              # Is ELECTO Admin?
                    keyManager.generateUUID(),      # UUID
                    data.mail,                      # E-Mail
                    None if devMode else confirmationCode,  # mldc fix  (confirmation code)
                    1 if devMode else 0                     # dar vienas mldc fix   (is account activated?)
                )
            )  
            
            database.commit()                                       # Commit to database
            database.close()                                        # Exit to allow other connections to database

            return {'response' : 'Registered successfully, activate acccount with provided code in email.'} # Respond with a success

    except mysql.connector.Error as db_error:                   # Respond with 500 if there is a database error
        raise HTTPException(status_code=500, detail=f"Database Error: {str(db_error)}")

    except Exception as e:                                      # Respond with 500 for unexpected errors
        raise HTTPException(status_code=500, detail=f"An unexpected error occurred: {str(e)}") 

class LoginRequest(BaseModel):                                  # Define a Pydantic model for login
    username : str
    password : str

@api.post('/login')                                             # Login
async def logform(data : LoginRequest):

    logd('[DEV - REMOVE IN PROD] Logging in with ' + data.username)

    database = sqlManager.connectDb()

    sqlCursor = sqlManager.createCursor(database)                          # Create MySQL cursor
    cursorCode = 'SELECT * FROM meowhosting.userdata WHERE user = %s'

    publicKey = keyManager.getPublicKey(privateKey)                         # Get public key

    validationPassword = keyManager.decrypt(data.password, privateKey)

    sqlCursor.execute(cursorCode, (data.username,))             # Find username and id with other details
    cursorResp = sqlCursor.fetchone()                           # Fetch data

    database.close()                                            # Close out

    if cursorResp:                                              # If successful response...

        encryptedPassword = cursorResp[2]                       # Get password from database
        salt = cursorResp[3]                                    # Get salt from database

        decryptedPass = keyManager.decrypt(encryptedPassword, privateKey)

        validationPassword = validationPassword.decode('utf-8') # Decode password from client to utf-8
        validationPassword = salt + validationPassword          # Add salt to client password

        if decryptedPass.decode('utf-8') == validationPassword: # If they match...
            token = keyManager.generateUUID()                           # Create a token

            database = sqlManager.connectDb()

            sqlCursor = sqlManager.createCursor(database)                       # Create database cursor

            cursorCode = 'UPDATE meowhosting.userdata SET token = %s WHERE user = %s'    

            sqlCursor.execute(cursorCode, (token, data.username))   # Set token inside database
            database.commit()                                       # Commit to database

            database.close()                                        # Exit MySQL database

            return {'response' : 'Authenticated', 'uuid' : cursorResp[5], 'token' : token}  # Respond with uuid and token for future authentication

        else:
           raise HTTPException(status_code=401, detail='Invalid username or password')      # If fail, return error

    else:
        raise HTTPException(status_code=401, detail='Invalid username or password')         # If fail, return error

class ActionRequestForm(BaseModel):                                 # Authentication PyDantic model for future requests
    userID   : str
    token    : str

@api.post('/logout')                                                # Logout
async def logout(data : ActionRequestForm):

    # THIS IS FOR DEBUGGING ONLY. REMOVE IN PRODUCTION!
    logd('[DEV - REMOVE IN PROD] Requesting logout with ' + data.userID + ' ' + data.token)

    if data.userID != 'NULL' or data.token != 'NULL':               # Check if received token and uuid are not NULL

        cursorCode = 'UPDATE meowhosting.userdata SET token = NULL WHERE userID = %s'

        database = sqlManager.connectDb()
    
        sqlCursor = sqlManager.createCursor(database)                               # Create database cursor

        sqlCursor.execute(cursorCode, (data.userID,))               # Destroy token
        database.commit()                                           # Commit to database

        database.close()                                            # Disconnect

        return {'response' : 'Logged out'}                          # Respond with a successfull code

    else:
        raise HTTPException(status_code=401, detail='Missing userID or token')

@api.post('/delete-account')                                        # Account deletion
async def delete(data: ActionRequestForm):
    logd('[DEV - REMOVE IN PROD] Deleting account')

    if data.userID != 'NULL' and data.token != 'NULL':
        logd('[DEV - REMOVE IN PROD]  Authenticating')

        database = sqlManager.connectDb()

        sqlCursor = sqlManager.createCursor(database)                               # Create database cursor

        authQuery = 'SELECT token FROM meowhosting.userdata WHERE userID = %s'
        sqlCursor.execute(authQuery, (data.userID,))                # Get user data and authenticate
        authResponse = sqlCursor.fetchone()

        if authResponse and authResponse[0] == data.token:          # If authentication is successfull...
            logd('[DEV - REMOVE IN PROD] Authenticated, deleting account')

            deleteQuery = 'DELETE FROM meowhosting.userdata WHERE userID = %s'
            sqlCursor.execute(deleteQuery, (data.userID,))          # Delete user entry
            database.commit()                                       # Commit to database

            database.close()                                        # Disconnect

            return {'response': 'Account deleted successfully'}     # Respond with success
        else:
            database.close()
            raise HTTPException(status_code=401, detail='Authentication failed')    # If authentication failed...
    else:
        raise HTTPException(status_code=401, detail='Missing userID or token')  # If missing uuid or token