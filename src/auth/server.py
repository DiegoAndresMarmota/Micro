import jwt
import datetime
import os
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
    try:
        auth = request.authorization
        if not auth:
            return "missing credentials", 401
    
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
    
#Server Run
if __name__ == "__main__":
    server.run(host="0.0.0.0", port=5000, debug=True)