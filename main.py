from fastapi import FastAPI, HTTPException, Depends
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from fastapi.security import OAuth2PasswordBearer
from typing import Optional
import mysql.connector
from typing import Union

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


def authenticate_admin(username: str, password: str):
    # Check if the provided username and password match an existing admin in the database
    check_query = "SELECT * FROM admin WHERE Username = %s AND Password = %s"
    check_values = (username, password)
    cursor.execute(check_query, check_values)
    existing_admin = cursor.fetchone()

    if existing_admin:
        return True
    return False

# Dependency to check if the request is coming from a valid admin
def get_current_admin(username: str = Depends(lambda x: x.headers.get("username")),
                      password: str = Depends(lambda x: x.headers.get("password"))):
    if not authenticate_admin(username, password):
        raise HTTPException(status_code=401, detail="Invalid admin credentials")
    return True

def authenticate_user(username: str, password: str, user_type: str):
    # Check if the provided username and password match a user in the specified database
    check_query = "SELECT * FROM {} WHERE Username = %s AND Password = %s".format(user_type)
    check_values = (username, password)
    cursor.execute(check_query, check_values)
    user = cursor.fetchone()

    if user:
        return user_type  # Return the user type (admin or user)
    return None

# Dependency to check if the request is coming from a valid admin
def get_current_user(login_data: UserLogin = Depends()):
    username = login_data.Username
    password = login_data.Password

    admin_auth = authenticate_user(username, password, "admin")
    if admin_auth:
        return {"user_type": "admin", "user_details": admin_auth[1]}
    
    user_auth = authenticate_user(username, password, "user")
    if user_auth:
        return {"user_type": "user", "user_details": user_auth[1]}
    
    raise HTTPException(status_code=401, detail="Invalid credentials")

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
            return User(**user_data)

        # Check if the provided username and password match the admin data
        cursor.execute("SELECT * FROM admin WHERE Username = %s AND Password = %s", (credentials.Username, credentials.Password))
        admin_data = cursor.fetchone()
        if admin_data:
            return Admin(**admin_data)

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Internal Server Error: {str(e)}")

    finally:
        # Close the database cursor and connection in the finally block
        if cursor:
            cursor.close()
        if connection and connection.is_connected():
            connection.close()

@app.post("/login")
async def user_login(credentials: UserLogin):
    user = login(credentials, db_config)
    
    if user is None:
        raise HTTPException(status_code=401, detail="Invalid credentials")

    return {"message": f"Welcome, {user.FirstName} {user.LastName}!"}

@app.get("/showuser")
def show_user(current_user: dict = Depends(get_current_user)):
    user_type = current_user['user_type']
    user_details = current_user['user_details']

    if user_type == "admin":
        # Display admin information or perform admin-specific actions
        return {"message": f"Displaying admin information: {user_details}"}
    elif user_type == "user":
        # Display user information or perform user-specific actions
        return {"message": f"Displaying user information: {user_details}"}


# Pydantic model for the reservation request
class Booking(BaseModel):
    BookingID: str
    UserID: str
    RoomID: str
    AdminID: str
    StartTime: str
    EndTime: str
    Status: str
    Timestamp:str


@app.post("/booking")
def booking(booking: Booking):
    try:
        # Insert reservation data into the MySQL database
        query = "INSERT INTO booking(StartTime, EndTime, Status, TimeStamp) VALUES (%s, %s, %s, %s)"
        values = (booking.StartTime, booking.EndTime, booking.Status, Booking.TimeStamp)
        cursor.execute(query, values)
        db.commit()
        return {"message": "Reservation created successfully"}
    except Exception as e:
        return HTTPException(status_code=500, detail=str(e))
    
@app.get("/showbooking")
def bookings():
    try:
        # Get all reservations from the MySQL database
        query = "SELECT * FROM booking"
        cursor.execute(query)
        result = cursor.fetchall()
        return result
    except Exception as e:
        return HTTPException(status_code=500, detail=str(e))
    
@app.post("/cancelroom")
def cancel_room(booking_id: str):
    try:
        # Check if the booking exists in the database
        check_query = "SELECT * FROM booking WHERE BookingID = %s"
        check_values = (booking_id,)
        cursor.execute(check_query, check_values)
        existing_booking = cursor.fetchone()

        if existing_booking:
            # Update the booking status to 'canceled'
            update_query = "UPDATE booking SET Status = 'canceled' WHERE BookingID = %s"
            update_values = (booking_id,)
            cursor.execute(update_query, update_values)
            db.commit()
            return {"message": f"Booking {booking_id} canceled successfully"}
        else:
            return HTTPException(status_code=404, detail=f"Booking {booking_id} not found")
    except Exception as e:
        return HTTPException(status_code=500, detail=str(e))

# Pydantic model for the room request
class Room(BaseModel):
    RoomID: int
    AdminID: int
    RoomName: str
    RoomType: str
    Description: str
    Availability: bool


@app.post("/room")
def room(room: Room):
    try:
        # Insert room data into the MySQL database
        query = "INSERT INTO room (RoomName, RoomType, Description , Availability) VALUES (%s, %s, %s, %s)"
        values = (room.RoomName, room.RoomType, room.Description, room.Availability)
        cursor.execute(query, values)
        db.commit()
        return {"message": "New Room created successfully"}
    except Exception as e:
        return HTTPException(status_code=500, detail=str(e))
    
@app.post("/updateroom")
def update_room(room: Room):
    try:
        # Check if the room exists in the database
        check_query = "SELECT * FROM room WHERE RoomID = %s"
        check_values = (room.RoomID,)
        cursor.execute(check_query, check_values)
        existing_room = cursor.fetchone()

        if existing_room:
            # Update the room data in the MySQL database
            update_query = "UPDATE room SET RoomName = %s, RoomType = %s, Description = %s, Availability = %s WHERE RoomID = %s"
            update_values = (room.RoomName, room.RoomType, room.Description, room.Availability, room.RoomID)
            cursor.execute(update_query, update_values)
            db.commit()
            return {"message": f"Room {room.RoomID} updated successfully"}
        else:
            return HTTPException(status_code=404, detail=f"Room {room.RoomID} not found")
    except Exception as e:
        return HTTPException(status_code=500, detail=str(e))

@app.post("/deleteroom")
def delete_room(room_id: int):
    try:
        # Check if the room exists in the database
        check_query = "SELECT * FROM room WHERE RoomID = %s"
        check_values = (room_id,)
        cursor.execute(check_query, check_values)
        existing_room = cursor.fetchone()

        if existing_room:
            # Delete the room from the MySQL database
            delete_query = "DELETE FROM room WHERE RoomID = %s"
            delete_values = (room_id,)
            cursor.execute(delete_query, delete_values)
            db.commit()
            return {"message": f"Room {room_id} deleted successfully"}
        else:
            return HTTPException(status_code=404, detail=f"Room {room_id} not found")
    except Exception as e:
        return HTTPException(status_code=500, detail=str(e))
    
@app.get("/showroom")
def rooms(current_user: User = Depends(get_current_user)):
    try:
        # Get all users from the MySQL database
        query = "SELECT * FROM room"
        cursor.execute(query)
        result = cursor.fetchall()

        # Check if the current user has permission to access the endpoint
        if current_user.Username == "admin":
            return result
        else:
            return HTTPException(status_code=403, detail="Permission denied")
    except Exception as e:
        return HTTPException(status_code=500, detail=str(e))

@app.get("/")
async def root():
    return {"message": "Hello World"}
