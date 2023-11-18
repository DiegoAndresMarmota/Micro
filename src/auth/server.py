import jwt
import datetime
import os
from multiprocessing import AuthenticationError
from flask import Flask, request
from flask_mysqldb import MySQL

server = Flask(__name__)
mysql = MySQL(server)

#Server Config
server.config["MYSQL_HOST"] = os.environ.get("MYSQL_HOST")
server.config["MYSQL_JOURNALIST"] = os.environ.get("MYSQL_JOURNALIST")
server.config["MYSQL_PASSWORD"] = os.environ.get("MYSQL_PASSWORD")
server.config["MYSQL_DB"] = os.environ.get("MYSQL_DB")
server.config["MYSQL_PORT"] = os.environ.get("MYSQL_PORT")

#Login
@server.route("/login", methods=["POST"])
def login( auth: str) -> dict:
    """
    The `login` function takes in an authentication token, checks if the credentials are valid, and
    returns a JWT token if the credentials are correct.
    
    :param auth: The `auth` parameter is a string that represents the authentication credentials. It is
    used to authenticate the user during the login process
    :type auth: str
    :return: different values based on different conditions:
    """
    try:
        auth = request.authorization
    except AuthenticationError:
        return "missing credentials", 400
    
    try:
        cur = mysql.connection.cursor()
        res = cur.execute(
            "SELECT email, password FROM journalist WHERE email=%s", (auth.journalist_name,)
        )

        if res > 0:
            user_row = cur.fetchone()
            email = user_row[0]
            password = user_row[1]
        
            if auth.journalist_name != email or auth.password != password:
                return "invalid credentials", 401
            else:
                return createJWT(auth.journalist_name, os.environ.get("JWT_SECRET"), True)
            
    except Exception as e:
            return "invalid credentials", 401
        
    finally:
        return "Login Successful", 202


def createJWT(journalist_name: str, secret: str, authz: bool) -> dict:
    """
    The function `createJWT` generates a JSON Web Token (JWT) with the provided journalist name, secret,
    and authorization flag, and returns a dictionary with a success message.
    
    :param journalist_name: The name of the journalist for whom the JWT token is being created
    :type journalist_name: str
    :param secret: The "secret" parameter is a string that is used as the secret key to encode and
    decode the JWT token. It should be a secure and unique value that is known only to the server
    :type secret: str
    :param authz: The parameter `authz` is a boolean value that indicates whether the journalist has
    administrative privileges or not. If `authz` is `True`, it means the journalist has administrative
    privileges, and if it is `False`, it means the journalist does not have administrative privileges
    :type authz: bool
    :return: a dictionary with a message indicating whether the JWT token was created successfully or
    not. If an exception is raised during the creation of the token, the function will return a
    dictionary with an error message and an appropriate status code.
    """
    try:
        return jwt.encode(
        {
            "journalist_name": journalist_name,
            "exp": datetime.datetime.now(tz=datetime.timezone.utc) + datetime.timedelta(minutes=120),
            "iat": datetime.datetime.utcnow(),
            "admin": authz,
        },
        secret, 
        algorithm="HS256",
    )
        
    # except Exception as e:
    #     return "Not create a JWT Token", 40X
    
    except jwt.JWTExtendedException as JWTExtendedException:
        return {'message': "Not create a JWT Token"}, 401
    
    except jwt.JWTDecodeError as JWTExtendedException:
        return {'message': "An error decoding a JWT"}, 402
    
    except jwt.InvalidHeaderError as JWTExtendedException:
        return {'message': "An error getting header information from a request"}, 403
    
    except jwt.InvalidQueryParamError as JWTExtendedException:
        return {'message': "An error when a query string param is not in the correct format"}, 404
    
    except jwt.NoAuthorizationError as JWTExtendedException:
        return {'message': "An error raised when no authorization token was found in a protected endpoint"}, 405
    
    except jwt.CRSFError as JWTExtendedException:
        return {'message': "An error with CSRF protection"}, 405
    
    except jwt.WrongTokenError as JWTExtendedException:
        return {'message': "Error raised when attempting to use a refresh token to access an endpoint or vice versa"}, 406
    
    except jwt.RevokedTokenError as JWTExtendedException:
        return {'message': "Error raised when a revoked token attempt to access a protected endpoint"}, 407
    
    except jwt.FreshTokenRequiredError as JWTExtendedException:
        return {'message': "Error raised when a valid, non-fresh JWT attempt to access an endpoint protected by fresh_jwt_required"}, 408
    
    except jwt.UserLookupError as JWTExtendedException:
        return {'message': "Error raised when a user_lookup callback function returns None, indicating that it cannot or will not load a user for the given identity"}, 409
    
    except jwt.UserClaimsVerificationError as JWTExtendedException:
        return {'message': "Error raised when the claims_verification_callback function returns False,indicating that the expected user claims are invalid"}, 410
    
    finally:
        return {'message': "JWT Token Created Successfully"}, 201


@server.route("/validate", method=["POST"])
def validate(token: str) -> dict:
    """
    The function `validate` takes a token as input, decodes it using a secret key, and returns the
    decoded token if it is valid, along with an appropriate status code and message.
    
    :param token: The `token` parameter is a string that represents the JWT (JSON Web Token) that needs
    to be validated
    :type token: str
    :return: a dictionary with a 'message' key and a corresponding value. The specific message being
    returned depends on the condition that is met in the try-except block.
    """
    try:
        encoded_jwt = request.headers.get("Authorization")
    except Exception as e:
        return {'message': "Missing credentials"}, 411
    
    try:
        decoded = jwt.decode(
            encoded_jwt, os.environ.get("JWT_SECRET"), algorithms=["HS256"]
        )
        return decoded, 200
        
    except jwt.ExpiredSignatureError as JWTExtendedException:
        return {'message': "Credentials not authorized"}, 403
    
    finally:
        return {'message': "Validate credentials"}, 202


#Server Run
if __name__ == "__main__":
    server.run(host="0.0.0.0", port=5000, debug=True)