from fastapi import FastAPI, HTTPException, Depends, Header
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from fastapi.security import OAuth2PasswordBearer
from typing import Optional
import mysql.connector
from typing import Union
from datetime import datetime

app = FastAPI()

# CORS (Cross-Origin Resource Sharing) middleware to allow communication with the frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# MySQL database configuration
db_config = {
    'host': 'localhost',
    'user': 'root',
    'password': 'root',
    'database': 'roomie',
}

db = mysql.connector.connect(**db_config)

cursor = db.cursor(dictionary=True)

# OAuth2PasswordBearer for authentication
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")


class User(BaseModel):
    FirstName: str
    LastName: str
    Email: str
    Username: str
    Password: str

class Admin(BaseModel):
    FirstName: str
    LastName: str
    Email: str
    Username: str
    Password: str

# Pydantic model for the login request
class UserLogin(BaseModel):
    Username: str
    Password: str

# Pydantic model for the room request
class Room(BaseModel):
    # fill the one that is not auto increment
    AdminID: str
    RoomName: str
    RoomType: str
    Description: str
    Availability: bool

class Booking(BaseModel):
    UserID: int
    RoomID: int
    AdminID: int
    StartTime: datetime
    EndTime: datetime
    Status: str
    Timestamp: datetime

class Cancellation(BaseModel):
    BookingID: int
    Timestamp: datetime

class Warning(BaseModel):
    TimeStamp: datetime

# to def get_current_admin
def authenticate_admin(username: str, password: str):
    # Check if the provided username and password match an existing admin in the database
    check_query = "SELECT * FROM admin WHERE Username = %s AND Password = %s"
    check_values = (username, password)
    cursor.execute(check_query, check_values)
    existing_admin = cursor.fetchone()

    if existing_admin:
        return existing_admin  # Return the admin details
    return None

# Dependency to check if the request is coming from a valid admin
# to @app.post("/signupadmin")
def get_current_admin(username: str = Depends(lambda x: x.headers.get("username")), 
                      password: str = Depends(lambda x: x.headers.get("password"))):
    admin_details = authenticate_admin(username, password)
    if admin_details:
        return {"user_type": "admin", "user_details": admin_details}
    
    raise HTTPException(status_code=401, detail="Invalid admin credentials")

# to def get_current_user 
def authenticate_user(username: str, password: str, user_type: str): 
    # Check if the provided username and password match a user in the specified database
    check_query = "SELECT * FROM {} WHERE Username = %s AND Password = %s".format(user_type)
    check_values = (username, password)
    cursor.execute(check_query, check_values)
    user = cursor.fetchone()

    if user:
        return user_type  # Return the user type (admin or user)
    return None

# to async def get_user_type
def extract_user_type(authorization: str) -> str:
    # Extract the user type from the authorization header
    user_type = authorization.split(" ")[0]
    return user_type

# to def get_current_user, @app.post("/logout")
async def get_user_type(authorization: Optional[str] = Header(None)):
    if authorization is None:
        raise HTTPException(status_code=401, detail="Unauthorized")

    user_type = extract_user_type(authorization)

    if user_type not in ["admin", "user"]:
        raise HTTPException(status_code=401, detail="Invalid user type")

    return user_type
    #return admin or user

# to @app.post("/signupadmin"), @app.get("/showuser"), @app.get("/showroom")
# Dependency to check if the request is coming from a valid admin
def get_current_user(user_type: str = Depends(get_user_type), login_data: UserLogin = Depends()):
    username = login_data.Username
    password = login_data.Password

    if user_type == "admin":
        admin_auth = authenticate_user(username, password, "admin")
        if admin_auth:
            return {"user_type": "admin", "user_details": admin_auth[1]}
    elif user_type == "user":
        user_auth = authenticate_user(username, password, "user")
        if user_auth:
            return {"user_type": "user", "user_details": user_auth[1]}
        
    raise HTTPException(status_code=401, detail="Invalid credentials")
    #from get_user_type, authenicate_user, return admin or user in details

@app.post("/signout")
def remove_current_user():
    return {"user_type": None, "user_details": None}

@app.post("/signupadmin", dependencies=[Depends(get_current_admin)])
def signupadmin(admin: Admin):
    try:
        # Check if the username already exists in the MySQL database
        check_query = "SELECT * FROM admin WHERE Username = %s"
        check_values = (admin.Username)
        cursor.execute(check_query, check_values)
        existing_admin = cursor.fetchone()

        if existing_admin:
            return HTTPException(status_code=400, detail="Username already exists. Please choose a different username.")
        
        # Insert user data into the MySQL database
        insert_query = "INSERT INTO admin(Username, Password) VALUES (%s, %s)"
        insert_values = (admin.Username, admin.Password)
        cursor.execute(insert_query, insert_values)
        db.commit()

        return {"message": "New Admin signed up successfully"}
    except Exception as e:
        return HTTPException(status_code=500, detail=str(e))


# Pydantic model for the signup reques
@app.post("/signup")
def signup(user: User):
    try:
        # Check if the username already exists in the MySQL database
        check_query = "SELECT * FROM user WHERE Username = %s"
        check_values = (user.Username,)  # Make sure to use a tuple here
        cursor.execute(check_query, check_values)
        existing_user = cursor.fetchone()

        if existing_user:
            return HTTPException(status_code=400, detail="Username already exists. Please choose a different username.")
        
        # Insert user data into the MySQL database
        insert_query = "INSERT INTO user (FirstName, LastName, Email, Username, Password, WarningCount) VALUES (%s, %s, %s, %s, %s, %s)"
        insert_values = (user.FirstName, user.LastName, user.Email, user.Username, user.Password, 0)  # 0 or NULL depending on your requirements
        cursor.execute(insert_query, insert_values)
        db.commit()

        return {"message": "New User signed up successfully"}
    except Exception as e:
        return HTTPException(status_code=500, detail=str(e))
    finally:
    # Close the database cursor and connection in the finally block
        if db and db.is_connected():
            cursor.close()
            db.close()

def login(credentials: UserLogin, db_config: dict) -> Union[User, Admin, None]:
    connection = None
    cursor = None
    try:
        # Establish a connection to the MySQL database
        connection = mysql.connector.connect(**db_config)
        cursor = connection.cursor(dictionary=True)

        # Check if the provided username and password match the user data
        cursor.execute("SELECT * FROM user WHERE Username = %s AND Password = %s", (credentials.Username, credentials.Password))
        user_data = cursor.fetchone()
        if user_data:
            # Return a dictionary with user details
            return {"user_type": "user", "user_details": user_data}

        # Check if the provided username and password match the admin data
        cursor.execute("SELECT * FROM admin WHERE Username = %s AND Password = %s", (credentials.Username, credentials.Password))
        admin_data = cursor.fetchone()
        if admin_data:
            # Return a dictionary with admin details
            return {"user_type": "admin", "user_details": admin_data}

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Internal Server Error: {str(e)}")

    finally:
        # Close the database cursor and connection in the finally block
        if cursor:
            cursor.close()
        if connection and connection.is_connected():
            connection.close()


@app.post("/signin")
async def user_signin(credentials: UserLogin):
    user_data = login(credentials, db_config)
    
    if user_data is None:
        raise HTTPException(status_code=401, detail="Invalid credentials")

    if user_data.get("user_type") == "admin":
        return {"message": f"Welcome, Admin {user_data['user_details']['Username']}!"}
    elif user_data.get("user_type") == "user":
        return {"message": f"Welcome, {user_data['user_details']['FirstName']} {user_data['user_details']['LastName']}!"}

@app.post("signout")
async def user_signout(current_user_type: Optional[str] = Depends(get_user_type)):
    if current_user_type is None:
        raise HTTPException(status_code=401, detail="User not logged in")

    # Perform any other necessary logout actions
    return {"message": "Logout successful", "user_type": None}

@app.get("/showuser")
def show_user(
    user_type: str = Depends(get_user_type)
):
    print(f"User_Type: {user_type}") #test
    if user_type != "admin":
        raise HTTPException(status_code=403, detail="Permission denied. Only admins can access this endpoint.")

    try:
        query = "SELECT * FROM users"
        cursor.execute(query)
        result = cursor.fetchall()
        return result
    except Exception as e:
        return HTTPException(status_code=500, detail=str(e))

@app.post("/addroom")
def add_room(
    user_type: str = Depends(get_user_type)
):
    if user_type != "admin":
        raise HTTPException(status_code=403, detail="Permission denied. Only admins can access this endpoint.")
    try:
        # Insert room data into the MySQL database
        query = "INSERT INTO room (AdminID, RoomName, RoomType, Description, Availability) VALUES (%s, %s, %s, %s, %s)"
        values = (Room.AdminID, Room.RoomName, Room.RoomType, Room.Description, Room.Availability)
        cursor.execute(query, values)
        db.commit()
        return {"message": "New Room created successfully"}
    except Exception as e:
        return HTTPException(status_code=500, detail=str(e))
    
@app.post("/updateroom")
def update_room(
    user_type: str = Depends(get_user_type)
):
    if user_type != "admin":
        raise HTTPException(status_code=403, detail="Permission denied. Only admins can access this endpoint.")

    try:
        # Update room data in the MySQL database
        query = "UPDATE room SET RoomName = %s, RoomType = %s, Description = %s, Availability = %s WHERE RoomID = %s"
        values = (Room.RoomName, Room.RoomType, Room.Description, Room.Availability, Room.RoomID)
        cursor.execute(query, values)
        db.commit()
        return {"message": "Room updated successfully"}
    except Exception as e:
        return HTTPException(status_code=500, detail=str(e))
    
@app.post("/deleteroom")
def delete_room(
    user_type: str = Depends(get_user_type)
):
    if user_type != "admin":
        raise HTTPException(status_code=403, detail="Permission denied. Only admins can access this endpoint.")
    try:
        # Delete room data from the MySQL database
        query = "DELETE FROM room WHERE RoomID = %s"
        values = (Room.RoomID)
        cursor.execute(query, values)
        db.commit()
        return {"message": "Room deleted successfully"}
    except Exception as e:
        return HTTPException(status_code=500, detail=str(e))
    
@app.get("/showroom")
def show_room():
    try:
        query = "SELECT * FROM room"
        cursor.execute(query)
        result = cursor.fetchall()
        return result
    except Exception as e:
        return HTTPException(status_code=500, detail=str(e))

    
@app.post("/bookroom")
def book_room(
    current_user: dict = Depends(get_current_user),
    user_type: str = Depends(get_user_type)
):
    if user_type == "user":
        try:
            # Insert booking data into the MySQL database
            query = "INSERT INTO booking (UserID, RoomID, AdminID, StartTime, EndTime, Status, Timestamp) VALUES (%s, %s, %s, %s, %s, %s, %s)"
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            values = ( current_user['user_details']['UserID'], Booking.RoomID, None, Booking.StartTime, Booking.EndTime, 'Pending',  timestamp )
            cursor.execute(query, values)
            db.commit()
            return {"message": "New Room Booking created successfully by User"}
        except Exception as e:
            return HTTPException(status_code=500, detail=str(e))
    elif user_type == "admin":
        try:
        # Insert booking data into the MySQL database
            query = "INSERT INTO booking (UserID, RoomID, AdminID, StartTime, EndTime, Status, Timestamp) VALUES (%s, %s, %s, %s, %s, %s, %s)"
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            values = (Booking.UserID, Booking.RoomID, current_user['user_details']['AdminID'], Booking.StartTime, Booking.EndTime, 'Pending',  timestamp)
            cursor.execute(query, values)
            db.commit()
            return {"message": "New Room Booking created successfully by Admin"}
        except Exception as e:
            return HTTPException(status_code=500, detail=str(e))
        
@app.post("/cancelbook")
def cancel_book(
    user_type: str = Depends(get_user_type)
):
    if user_type == "user":
        try:
            # Update booking data and insert data into CANCELLATION table in the MySQL database
            query = """
            UPDATE booking SET Status = %s WHERE BookingID = %s;
            INSERT INTO CANCELLATION (BookingID, Timestamp) VALUES (%s, %s);
            """
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            values = ('Cancelled', Cancellation.BookingID, Cancellation.BookingID, timestamp)
            cursor.execute(query, values)
            db.commit()
            return {"message": "Room Booking cancelled successfully by User"}
        except Exception as e:
            return HTTPException(status_code=500, detail=str(e))
    elif user_type == "admin":
        try:
            # Update booking data in the MySQL database
            query = """
            UPDATE booking SET Status = %s WHERE BookingID = %s;
            INSERT INTO CANCELLATION (BookingID, Timestamp) VALUES (%s, %s);
            """
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            values = ('Cancelled', Cancellation.BookingID, Cancellation.BookingID, timestamp)
            cursor.execute(query, values)
            db.commit()
            return {"message": "Room Booking cancelled successfully by Admin"}
        except Exception as e:
            return HTTPException(status_code=500, detail=str(e))
        
@app.post("/confirmbook")
def confirm_book(
    user_type: str = Depends(get_user_type)
):
    if user_type == "admin":
        try:
            # Update booking data in the MySQL database
            query = "UPDATE booking SET Status = %s WHERE BookingID = %s"
            values = ('Confirmed', Booking.BookingID)
            cursor.execute(query, values)
            db.commit()
            return {"message": "Room Booking confirmed successfully by Admin"}
        except Exception as e:
            return HTTPException(status_code=500, detail=str(e))
    else:
        return HTTPException(status_code=401, detail="Invalid user type")
    
    
@app.get("/showbookings")
def show_bookings(
    current_user: dict = Depends(get_current_user),
    user_type: str = Depends(get_user_type)
):
    if user_type == "admin":
        # Display all room bookings for admin
        try:
            query = "SELECT * FROM booking"
            cursor.execute(query)
            result = cursor.fetchall()
            return result
        except Exception as e:
            return HTTPException(status_code=500, detail=str(e))
    elif user_type == "user":
        # Display only the room bookings for the current user
        try:
            user_id = current_user['user_details']['UserID']
            query = "SELECT * FROM booking WHERE UserID = %s"
            cursor.execute(query, (user_id,))
            result = cursor.fetchall()
            return result
        except Exception as e:
            return HTTPException(status_code=500, detail=str(e))
    else:
        return HTTPException(status_code=401, detail="Invalid user type")
    
@app.post("/addwarning")
def add_warning(
    user_type: str = Depends(get_user_type)
):
    if user_type != "admin":
        raise HTTPException(status_code=403, detail="Permission denied. Only admins can access this endpoint.")
    try:
        # Insert warning data into the MySQL database
        query = "INSERT INTO warning (UserID, Timestamp) VALUES (%s, %s)"
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        values = (Warning.UserID, timestamp)
        cursor.execute(query, values)
        db.commit()
        return {"message": "New Warning created successfully by User"}
    except Exception as e:
        return HTTPException(status_code=500, detail=str(e))
    
@app.post("/showwarnings")
def show_warnings(
    current_user: dict = Depends(get_current_user),
    user_type: str = Depends(get_user_type)
):
    if user_type == "admin":
        # Display all warnings for admin
        try:
            query = "SELECT * FROM warning"
            cursor.execute(query)
            result = cursor.fetchall()
            return result
        except Exception as e:
            return HTTPException(status_code=500, detail=str(e))
    elif user_type == "user":
        # Display only the warnings for the current user
        try:
            user_id = current_user['user_details']['UserID']
            query = "SELECT * FROM warning WHERE UserID = %s"
            cursor.execute(query, (user_id,))
            result = cursor.fetchall()
            return result
        except Exception as e:
            return HTTPException(status_code=500, detail=str(e))
    else:
        return HTTPException(status_code=401, detail="Invalid user type")

@app.get("/")
async def root():
    return {"message": "Hello World"}
