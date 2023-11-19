from fastapi import FastAPI, HTTPException, Depends, Header
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
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

class Booking:
    UserID: int
    RoomID: int
    StartTime: str
    EndTime: str

class Cancellation(BaseModel):
    BookingID: int

class Warning(BaseModel):
    BookingID: int
    UserID: int

global usertypecheck, currentuserid, currentadminid

# to async def get_user_type for signout
def extract_user_type(authorization: str) -> str:
    # Extract the user type from the authorization header
    user_type = authorization.split(" ")[0]
    return user_type

# to def  @app.post("/signout")
async def get_user_type(authorization: Optional[str] = Header(None)):
    if authorization is None:
        raise HTTPException(status_code=401, detail="Unauthorized")

    user_type = extract_user_type(authorization)

    if user_type not in ["admin", "user"]:
        raise HTTPException(status_code=401, detail="Invalid user type")

    return user_type
    #return admin or user

@app.post("/signout")
def remove_current_user():
    return {"user_type": None, "user_details": None}

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

@app.post("/signupadmin")
def signupadmin(admin: Admin):
    if usertypecheck == "admin":
        try:
            # Check if the username already exists in the MySQL database
            check_query = "SELECT * FROM admin WHERE Username = %s"
            check_values = (admin.Username,)
            cursor.execute(check_query, check_values)
            existing_admin = cursor.fetchone()

            if existing_admin:
                return HTTPException(status_code=400, detail="Username already exists. Please choose a different username.")
            
            # Insert user data into the MySQL database
            insert_query = "INSERT INTO admin (FirstName, LastName, Email, Username, Password) VALUES (%s, %s, %s, %s, %s)"
            insert_values = (admin.FirstName, admin.LastName, admin.Email, admin.Username, admin.Password)  # 0 or NULL depending on your requirements
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
    global usertypecheck  # Declare usertypecheck as a global variable
    usertypecheck = ""  # Clear the contents of usertypecheck
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
            usertypecheck = "admin"
            # Return a dictionary with user details
            return {"user_type": "user", "user_details": user_data}

        # Check if the provided username and password match the admin data
        cursor.execute("SELECT * FROM admin WHERE Username = %s AND Password = %s", (credentials.Username, credentials.Password))
        admin_data = cursor.fetchone()
        if admin_data:
            usertypecheck = "user"
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
    global usertypecheck, currentuserid, currentadminid
    usertypecheck = ""
    currentuserid = ""
    currentadminid = ""
    user_data = login(credentials, db_config)
    
    if user_data is None:
        raise HTTPException(status_code=401, detail="Invalid credentials")

    if user_data.get("user_type") == "admin":
        usertypecheck = "admin"
        currentadminid = user_data['user_details']['AdminID']
        return {"message": f"Welcome, {user_data['user_details']['Username']}!, as {usertypecheck}"}
    elif user_data.get("user_type") == "user":
        usertypecheck = "user"
        currentuserid = user_data['user_details']['UserID']
        return {"message": f"Welcome, {user_data['user_details']['FirstName']} {user_data['user_details']['LastName']}!, , as {usertypecheck}"}
        
@app.post("signout")
async def user_signout(current_user_type: Optional[str] = Depends(get_user_type)):
    if current_user_type is None:
        raise HTTPException(status_code=401, detail="User not logged in")

    # Perform any other necessary logout actions
    return {"message": "Logout successful", "user_type": None}

@app.get("/showuser")
def show_user():
    global usertypecheck
    print(f"User_Type: {usertypecheck}")
    if usertypecheck != "admin":
        raise HTTPException(status_code=403, detail="Permission denied. Only admins can access this endpoint.")

    try:
        query = "SELECT * FROM user"
        cursor.execute(query)
        result = cursor.fetchall()
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/addroom")
def add_room(room: dict):
    global usertypecheck
    print(f"User_Type: {usertypecheck}")
    
    if usertypecheck != "admin":
        raise HTTPException(status_code=403, detail="Permission denied. Only admins can access this endpoint.")

    try:
        # Insert room data into the MySQL database
        query = "INSERT INTO room (AdminID, RoomName, RoomType, Description) VALUES (%s, %s, %s, %s)"
        values = (int(currentadminid), room.get('RoomName'), room.get('RoomType'), room.get('Description'))

        cursor.execute(query, values)
        db.commit()

        return {"message": "New Room created successfully"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    
# You can choose to edit some attribute or every attr.
@app.post("/updateroom")
def update_room(room: dict):
    global usertypecheck
    if usertypecheck != "admin":
        raise HTTPException(status_code=403, detail="Permission denied. Only admins can access this endpoint.")

    try:
        # Update room data in the MySQL database
        query = "UPDATE room SET "
        update_values = []
        
        if room.get('RoomName'):
            query += "RoomName = %s, "
            update_values.append(room.get('RoomName'))

        if room.get('RoomType'):
            query += "RoomType = %s, "
            update_values.append(room.get('RoomType'))

        if room.get('Description'):
            query += "Description = %s, "
            update_values.append(room.get('Description'))

        # Remove the trailing comma and space
        query = query.rstrip(', ')

        # Add the WHERE clause
        query += " WHERE RoomID = %s"
        update_values.append(room.get('RoomID'))
        cursor.execute(query, update_values)
        db.commit()
        return {"message": "Room updated successfully"}
    except Exception as e:
        return HTTPException(status_code=500, detail=str(e))
    
@app.post("/deleteroom")
def delete_room(room: dict):
    global usertypecheck
    if usertypecheck != "admin":
        raise HTTPException(status_code=403, detail="Permission denied. Only admins can access this endpoint.")

    try:
        # Delete room data from the MySQL database
        query = "DELETE FROM room WHERE RoomID = %s"
        values = (room.get('RoomID'),)
        cursor.execute(query, values)
        db.commit()
        return {"message": "Room deleted successfully"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    
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
async def book_room( booking: dict):
    global usertypecheck, currentadminid, currentuserid

    try:
        # Insert booking data into the MySQL database
        query_user = "INSERT INTO booking (UserID, RoomID, StartTime, EndTime, Status, Timestamp) VALUES (%s, %s, %s, %s, %s, %s)"
        query_admin = "INSERT INTO booking (UserID, RoomID, AdminID, StartTime, EndTime, Status, Timestamp) VALUES (%s, %s, %s, %s, %s, %s, %s)"
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        if usertypecheck == "user":
            values_user = (int(currentuserid), booking.get('RoomID'), booking.get('StartTime'), booking.get('EndTime'), 'Pending', timestamp)
            cursor.execute(query_user, values_user)
        elif usertypecheck == "admin":
            values_admin = (booking.get('UserID'), booking.get('RoomID'), int(currentadminid), booking.get('StartTime'), booking.get('EndTime'), 'Pending', timestamp)
            cursor.execute(query_admin, values_admin)

        db.commit()
        return {"message": f"New Room Booking created successfully by {usertypecheck}"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    
@app.post("/confirmbook")
async def confirm_book(booking: dict):
    global usertypecheck
    if usertypecheck == "admin":
        try:
            # Update booking data in the MySQL database
            query = "UPDATE booking SET Status = %s WHERE BookingID = %s"
            update_values = ["Confirmed", booking.get('BookingID')]

            cursor.execute(query, update_values)
            db.commit()
            return {"message": "Room Booking confirmed successfully by Admin"}
        except Exception as e:
            return HTTPException(status_code=500, detail=str(e))
    else:
        return HTTPException(status_code=401, detail="Invalid user type")

@app.post("/removebook") 
async def remove_book(booking: dict):
    global usertypecheck
    if usertypecheck == "admin":
        try:
            # Update booking data in the MySQL database
            query = "UPDATE booking SET Status = %s WHERE BookingID = %s"
            update_values = ["Removed by Admin", booking.get('BookingID')]

            cursor.execute(query, update_values)
            db.commit()
            return {"message": "Room Booking removed successfully by Admin"}
        except Exception as e:
            return HTTPException(status_code=500, detail=str(e))
    else:
        return HTTPException(status_code=401, detail="Invalid user type")
        
@app.post("/cancelbook")
async def cancel_book(cancellation: Cancellation):
    global usertypecheck
    if usertypecheck == "user":
        try:
            # Start a transaction
            db.start_transaction()

            # Update booking data in the MySQL database
            query_booking = "UPDATE booking SET Status = %s WHERE BookingID = %s"
            update_values_booking = ["Cancelled by User", cancellation.BookingID]
            db.cursor().execute(query_booking, update_values_booking)

            # Insert data into the CANCELLATION table
            query_cancellation = "INSERT INTO CANCELLATION (BookingID, Timestamp) VALUES (%s, NOW())"
            values_cancellation = [cancellation.BookingID]
            db.cursor().execute(query_cancellation, values_cancellation)

            # Commit the transaction
            db.commit()

            return {"message": "Room Booking cancelled successfully by User"}
        except Exception as e:
            # Rollback in case of an exception
            db.rollback()
            return HTTPException(status_code=500, detail=str(e))
        finally:
            # Close the cursor
            db.cursor().close()
            # Close the connection
            db.close()

    elif usertypecheck == "admin":
        try:
            # Start a transaction
            db.start_transaction()

            # Update booking data in the MySQL database
            query_booking = "UPDATE booking SET Status = %s WHERE BookingID = %s"
            update_values_booking = ["Cancelled by Admin", cancellation.BookingID]
            db.cursor().execute(query_booking, update_values_booking)

            # Insert data into the CANCELLATION table
            query_cancellation = "INSERT INTO CANCELLATION (BookingID, Timestamp) VALUES (%s, NOW())"
            values_cancellation = [cancellation.BookingID]
            db.cursor().execute(query_cancellation, values_cancellation)

            # Commit the transaction
            db.commit()

            return {"message": "Room Booking cancelled successfully by Admin"}
        except Exception as e:
            # Rollback in case of an exception
            db.rollback()
            return HTTPException(status_code=500, detail=str(e))
        finally:
            # Close the cursor
            db.cursor().close()
            # Close the connection
            db.close()

@app.get("/showbookings")
def show_bookings():
    global usertypecheck, currentuserid, currentadminid
    if usertypecheck == "admin":
        # Display all room bookings for admin
        try:
            query = "SELECT * FROM booking"
            cursor.execute(query)
            result = cursor.fetchall()
            return result
        except Exception as e:
            return HTTPException(status_code=500, detail=str(e))
    elif usertypecheck == "user":
        # Display only the room bookings for the current user
        try:
            user_id = int(currentuserid)
            query = "SELECT * FROM booking WHERE UserID = %s"
            cursor.execute(query, (user_id,))
            result = cursor.fetchall()
            return result
        except Exception as e:
            return HTTPException(status_code=500, detail=str(e))
    else:
        return HTTPException(status_code=401, detail="Invalid user type")
    
@app.post("/addwarning")
def add_warning(warning: Warning):
    global usertypecheck
    if usertypecheck != "admin":
        raise HTTPException(status_code=403, detail="Permission denied. Only admins can access this endpoint.")
    try:
        # Insert warning data into the MySQL database
        query = "INSERT INTO warning (BookingID, UserID, Timestamp) VALUES (%s, %s, %s)"
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        values = (warning.BookingID, warning.UserID, timestamp)
        cursor.execute(query, values)
        db.commit()
        return {"message": "New Warning created successfully by Admin"}
    except Exception as e:
        return HTTPException(status_code=500, detail=str(e))
    
@app.get("/showwarnings")
def show_warnings():
    global usertypecheck, currentadminid, currentuserid
    if usertypecheck == "admin":
        # Display all warnings for admin
        try:
            query = "SELECT * FROM warning"
            cursor.execute(query)
            result = cursor.fetchall()
            return result
        except Exception as e:
            return HTTPException(status_code=500, detail=str(e))
    elif usertypecheck == "user":
        # Display only the warnings for the current user
        try:
            user_id = int(currentuserid)
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
