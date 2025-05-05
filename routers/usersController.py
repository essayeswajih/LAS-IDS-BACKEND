from datetime import datetime, timedelta
from typing import Annotated, List
from pydantic import BaseModel, EmailStr
from sqlalchemy import desc, func, text
from starlette import status
from sqlalchemy.orm import Session
from fastapi import APIRouter, Depends, HTTPException,status
from db.database import get_db
from models.Intrusion_detected_entity import IntrusionDetected
from models.contact_entity import Contact
from models.report_entity import Report
from models.rowEntity import Row
from models.logs_entity import Log
from schemas.logDTO import LogDTO, LogWithoutRowsDTO
from models.usersEntity import RoleEnum, User
from routers.auth import generate_unique_username, get_current_user, get_key, bcrypt_context, validate_user_email
from schemas.userDTO import UserDTO, UserLiteDTO

router = APIRouter(tags = ["user"])

@router.get("/users/", response_model=List[UserLiteDTO])
def get_users(
    user_data: Annotated[dict, Depends(get_current_user)],
    db: Session = Depends(get_db)
):
    user = db.query(User).filter_by(username=user_data["username"], id=user_data["id"]).first()
    if user is None or user.role != RoleEnum.admin:  # Compare with enum value
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Authentication failed.")
    
    all_users = db.query(User).all()
    return all_users
        
@router.get("/users/get_one_by_id/{id}", response_model=UserLiteDTO)
def get_user_by_id(
    id: int,
    user_data: Annotated[dict, Depends(get_current_user)],
    db: Session = Depends(get_db)
):
    user = db.query(User).filter_by(username=user_data["username"], id=user_data["id"]).first()
    if user is None or user.role != RoleEnum.admin:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Authentication failed.")

    userx = db.query(User).filter_by(id=id).first()
    if userx is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found.")
    return userx

@router.post("/users/", response_model=UserLiteDTO, status_code=status.HTTP_201_CREATED)
def create_user(
    user_data: UserDTO,
    current_user_data: Annotated[dict, Depends(get_current_user)],
    db: Session = Depends(get_db)
):
    # Authenticate the current user and check if they are an admin
    current_user = db.query(User).filter_by(username=current_user_data["username"], id=current_user_data["id"]).first()
    print("detected user", current_user.role)  # Debugging output
    if current_user is None or current_user.role != RoleEnum.admin:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Authentication failed.")

    # Validate email uniqueness
    if not validate_user_email(db, user_data.email):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Email already exists.")

    # Generate username if not provided, otherwise check for uniqueness
    username = user_data.username
    if not username and user_data.firstName and user_data.lastName:
        username = generate_unique_username(db, user_data.firstName, user_data.lastName)
    elif username and db.query(User).filter_by(username=username).first():
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Username already exists")

    # Create new user instance
    new_user = User(
        firstName=user_data.firstName,
        lastName=user_data.lastName,
        company=user_data.company,
        email=user_data.email,
        username=username,
        hashed_password=bcrypt_context.hash(user_data.hashed_password) if user_data.hashed_password else None,
        role=user_data.role,
        room_name=user_data.room_name if user_data.room_name else get_key(),
        notifications=[]
    )
    db.add(new_user)
    db.commit()
    db.refresh(new_user)  # Refresh to get the generated id

    return new_user

@router.delete("/users/{id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_user(
    id: int,
    user_data: Annotated[dict, Depends(get_current_user)],
    db: Session = Depends(get_db)
):
    # Authenticate the current user
    current_user = db.query(User).filter_by(username=user_data["username"], id=user_data["id"]).first()
    if current_user is None or current_user.role != RoleEnum.admin:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Authentication failed.")

    # Find the user to delete
    user_to_delete = db.query(User).filter_by(id=id).first()
    if user_to_delete is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found.")

    # Delete the user
    db.delete(user_to_delete)
    db.commit()
    return None  # No content response

@router.put("/users/{id}", response_model=UserLiteDTO)
def update_user(
    id: int,
    user_update: UserLiteDTO,
    user_data: Annotated[dict, Depends(get_current_user)],
    db: Session = Depends(get_db)
):
    # Authenticate the current user
    current_user = db.query(User).filter_by(username=user_data["username"], id=user_data["id"]).first()
    if current_user is None or current_user.role != RoleEnum.admin:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Authentication failed.")

    # Find the user to update
    user_to_update = db.query(User).filter_by(id=id).first()
    if user_to_update is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found.")

    # Update fields (only those provided in the request)
    update_data = user_update.dict(exclude_unset=True)  # Only update fields that were sent
    for key, value in update_data.items():
        setattr(user_to_update, key, value)

    db.commit()
    db.refresh(user_to_update)
    return user_to_update

@router.get("/users/authorized_user", response_model=UserLiteDTO)
def get_authorized_user(
    user_data: Annotated[dict, Depends(get_current_user)],
    db: Session = Depends(get_db)
):
    print(user_data)
    
    user = db.query(User).filter_by(username=user_data["username"], id=user_data["id"]).first()

    if user is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Authentication failed.")
    return user

@router.get("/users/logs", response_model=list[LogWithoutRowsDTO])
def get_logs_by_user(
    user_data: Annotated[dict, Depends(get_current_user)],
    db: Session = Depends(get_db)
):
    user = db.query(User).filter_by(username=user_data["username"], id=user_data["id"]).first()
    if user is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Authentication failed.")

    return user.logs

@router.get("/users/get/room_name", response_model=list[LogDTO])
def get_room_name(user_data: Annotated[dict, Depends(get_current_user)],db: Session = Depends(get_db)):
    user = db.query(User).filter_by(username=user_data["username"], id=user_data["id"]).first()
    if user is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Authentication failed.")
    
    return user.room_name

@router.get("/users/set/room_name", response_model=str) 
def set_room_name(user_data: Annotated[dict, Depends(get_current_user)], db: Session = Depends(get_db)):
    user = db.query(User).filter_by(username=user_data["username"], id=user_data["id"]).first()
    if user is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Authentication failed.")

    user.room_name = get_key() 
    db.commit()
    db.refresh(user)

    return user.room_name

@router.get("/users/logs_count", response_model=int) 
def get_logs_count(user_data: Annotated[dict, Depends(get_current_user)], db: Session = Depends(get_db)):
    user = db.query(User).filter_by(username=user_data["username"], id=user_data["id"]).first()
    if user is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Authentication failed.")
    return len(user.logs)

@router.get("/users/rows_count", response_model=int) 
def get_rows_count(user_data: Annotated[dict, Depends(get_current_user)], db: Session = Depends(get_db)):
    user = db.query(User).filter_by(username=user_data["username"], id=user_data["id"]).first()
    if user is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Authentication failed.")
    return sum(log.rows_count for log in user.logs)

class ContactRequest(BaseModel):
    name: str
    email: EmailStr
    subject: str
    message: str

class ContactResponse(BaseModel):
    id: int
    name: str
    email: EmailStr
    subject: str
    message: str

    class Config:
        from_attributes = True

@router.post("/contact", status_code=status.HTTP_201_CREATED)
def submit_contact(contact_data: ContactRequest, db: Session = Depends(get_db)):
    try:
        new_contact = Contact(
            name=contact_data.name,
            email=contact_data.email,
            subject=contact_data.subject,
            message=contact_data.message
        )
        db.add(new_contact)
        db.commit()
        db.refresh(new_contact)

        return {"message": "Contact request received"}
    except:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Error occurred while sending message.")

# GET - Retrieve all messages
@router.get("/contact", response_model=list[ContactResponse])
def get_all_contacts(
    user_data: Annotated[dict, Depends(get_current_user)],
    db: Session = Depends(get_db)
    ):
    user = db.query(User).filter_by(username=user_data["username"], id=user_data["id"]).first()
    if user is None or user.role != RoleEnum.admin: 
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Authentication failed.")
    return db.query(Contact).all()

# DELETE - Delete message by ID
@router.delete("/contact/{id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_contact(id: int, user_data: Annotated[dict, Depends(get_current_user)], db: Session = Depends(get_db)):
    user = db.query(User).filter_by(username=user_data["username"], id=user_data["id"]).first()
    if user is None or user.role != RoleEnum.admin: 
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Authentication failed.")
    contact = db.query(Contact).filter(Contact.id == id).first()
    if not contact:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Message not found")
    db.delete(contact)
    db.commit()
    return 

@router.get("/AnalyticLog", response_model=dict)
def get_analytic_log(user_data: Annotated[dict, Depends(get_current_user)], db: Session = Depends(get_db)):
    user = db.query(User).filter_by(username=user_data["username"], id=user_data["id"]).first()
    if user is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Authentication failed.")
    
    # Dynamic date variables
    current_date = datetime.now()
    current_year = current_date.year
    current_year_start = datetime(current_year, 1, 1)
    last_year_start = datetime(current_year - 1, 1, 1)
    last_year_end = datetime(current_year - 1, 12, 31, 23, 59, 59)

    # Function to calculate percentage change and determine icon/color
    def get_change_stats(current: float, last: float):  # Updated to float for size compatibility
        if last == 0:  # Avoid division by zero
            percentage = 100.0 if current > 0 else 0.0
        else:
            percentage = ((current - last) / last) * 100
        percentage_str = f"{abs(percentage):.1f}%"
        icon = "rise" if percentage >= 0 else "fall"
        color = "text-primary" if percentage >= 0 else "text-warning"
        background = "bg-light-primary" if percentage >= 0 else "bg-light-warning"
        border = "border-primary" if percentage >= 0 else "border-warning"
        return percentage_str, icon, color, background, border

    if user.role == RoleEnum.admin:
        # Admin stats: Aggregate across all users
        # This year's stats
        total_users = db.query(User).count()
        total_log_counts = db.query(Log).filter(Log.created_at >= current_year_start).count()
        total_size = db.query(func.sum(Log.size)).filter(Log.created_at >= current_year_start).scalar() or 0.0
        total_pro_users = db.query(User).filter(User.role == RoleEnum.pro, User.created_at >= current_year_start).count()

        # Last year's stats
        last_total_users = db.query(User).filter(User.created_at.between(last_year_start, last_year_end)).count()
        last_total_log_counts = db.query(Log).filter(Log.created_at.between(last_year_start, last_year_end)).count()
        last_total_size = db.query(func.sum(Log.size)).filter(Log.created_at.between(last_year_start, last_year_end)).scalar() or 0.0
        last_total_pro_users = db.query(User).filter(User.role == RoleEnum.pro, User.created_at.between(last_year_start, last_year_end)).count()

        # Calculate stats for each metric
        users_pct, users_icon, users_color, users_bg, users_border = get_change_stats(total_users, last_total_users)
        logs_pct, logs_icon, logs_color, logs_bg, logs_border = get_change_stats(total_log_counts, last_total_log_counts)
        size_pct, size_icon, size_color, size_bg, size_border = get_change_stats(total_size, last_total_size)
        pro_users_pct, pro_users_icon, pro_users_color, pro_users_bg, pro_users_border = get_change_stats(total_pro_users, last_total_pro_users)

        return {
            "analytics": [
                {
                    "title": "Total Users",
                    "amount": str(total_users),
                    "background": users_bg,
                    "border": users_border,
                    "icon": users_icon,
                    "percentage": users_pct,
                    "color": users_color,
                    "number": str(total_users)
                },
                {
                    "title": "Total Logs",
                    "amount": str(total_log_counts),
                    "background": logs_bg,
                    "border": logs_border,
                    "icon": logs_icon,
                    "percentage": logs_pct,
                    "color": logs_color,
                    "number": str(total_log_counts)
                },
                {
                    "title": "Total Size",
                    "amount": f"{total_size:.2f} MB",  # Float formatting for MB
                    "background": size_bg,
                    "border": size_border,
                    "icon": size_icon,
                    "percentage": size_pct,
                    "color": size_color,
                    "number": f"{total_size:.2f} MB"
                },
                {
                    "title": "Total Pro Users",
                    "amount": str(total_pro_users),
                    "background": pro_users_bg,
                    "border": pro_users_border,
                    "icon": pro_users_icon,
                    "percentage": pro_users_pct,
                    "color": pro_users_color,
                    "number": str(total_pro_users)
                }
            ]
        }
    else:
        # Non-admin stats: User-specific
        total_log_files = len([log for log in user.logs if log.created_at >= current_year_start])
        total_rows = sum(log.rows_count for log in user.logs if log.created_at >= current_year_start) if user.logs else 0
        total_size = sum(log.size for log in user.logs if log.created_at >= current_year_start) if user.logs else 0
        total_alerts = len([notif for notif in user.notifications if hasattr(notif, 'created_at') and notif.created_at >= current_year_start]) if user.notifications else 0

        last_year_logs = [log for log in user.logs if last_year_start <= log.created_at <= last_year_end]
        last_year_notifications = [notif for notif in user.notifications if hasattr(notif, 'created_at') and last_year_start <= notif.created_at <= last_year_end]
        last_total_log_files = len(last_year_logs)
        last_total_rows = sum(log.rows_count for log in last_year_logs) if last_year_logs else 0
        last_total_size = sum(log.size for log in last_year_logs) if last_year_logs else 0
        last_total_alerts = len(last_year_notifications)

        # Calculate stats for each metric
        log_files_pct, log_files_icon, log_files_color, log_files_bg, log_files_border = get_change_stats(total_log_files, last_total_log_files)
        rows_pct, rows_icon, rows_color, rows_bg, rows_border = get_change_stats(total_rows, last_total_rows)
        size_pct, size_icon, size_color, size_bg, size_border = get_change_stats(total_size, last_total_size)
        alerts_pct, alerts_icon, alerts_color, alerts_bg, alerts_border = get_change_stats(total_alerts, last_total_alerts)

        return {
            "analytics": [
                {
                    "title": "Total Log Files",
                    "amount": str(total_log_files),
                    "background": log_files_bg,
                    "border": log_files_border,
                    "icon": log_files_icon,
                    "percentage": log_files_pct,
                    "color": log_files_color,
                    "number": str(total_log_files)
                },
                {
                    "title": "Total Events",
                    "amount": str(total_rows),
                    "background": rows_bg,
                    "border": rows_border,
                    "icon": rows_icon,
                    "percentage": rows_pct,
                    "color": rows_color,
                    "number": str(total_rows)
                },
                {
                    "title": "Total Size",
                    "amount": f"{total_size:.2f} MB",  # Float formatting for MB
                    "background": size_bg,
                    "border": size_border,
                    "icon": size_icon,
                    "percentage": size_pct,
                    "color": size_color,
                    "number": f"{total_size:.2f} MB"
                },
                {
                    "title": "Total Alerts",
                    "amount": str(total_alerts),
                    "background": alerts_bg,
                    "border": alerts_border,
                    "icon": alerts_icon,
                    "percentage": alerts_pct,
                    "color": alerts_color,
                    "number": str(total_alerts)
                }
            ]
        }
    
@router.get("/users/ChartData0", response_model=dict)
def get_chart_data(
    user_data: Annotated[dict, Depends(get_current_user)],
    period: str = "week",  # Query parameter: "week" or "month"
    db: Session = Depends(get_db)
):
    user = db.query(User).filter_by(username=user_data["username"], id=user_data["id"]).first()
    if user is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Authentication failed.")

    # Set time range based on period
    current_date = datetime.now()
    if period == "month":
        days = 365
        categories = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec']
    else:  # week
        days = 7
        categories = ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun']

    start_date = current_date - timedelta(days=days)

    if user.role == RoleEnum.admin:
        # Admin gets all data
        intrusions = db.query(IntrusionDetected).join(Report).filter(
            Report.created_at >= start_date
        ).all()
        reports = db.query(Report).filter(
            Report.created_at >= start_date
        ).all()
    else:
        # Regular user gets their own data
        intrusions = db.query(IntrusionDetected).join(Report).filter(
            Report.user_id == user.id,
            Report.created_at >= start_date
        ).all()
        reports = db.query(Report).filter(
            Report.user_id == user.id,
            Report.created_at >= start_date
        ).all()

    # Aggregate data by day/week/month
    intrusion_counts = {}
    report_counts = {}
    
    for i in range(days):
        date = start_date + timedelta(days=i)
        if period == "month":
            key = date.strftime("%b")  # Month abbreviation
        else:
            key = date.strftime("%a")  # Day abbreviation
        
        intrusion_counts[key] = 0
        report_counts[key] = 0

    # Count intrusions using Report.created_at
    for intrusion in intrusions:
        if period == "month":
            key = intrusion.report.created_at.strftime("%b")
        else:
            key = intrusion.report.created_at.strftime("%a")
        intrusion_counts[key] = intrusion_counts.get(key, 0) + 1

    # Count reports
    for report in reports:
        if period == "month":
            key = report.created_at.strftime("%b")
        else:
            key = report.created_at.strftime("%a")
        report_counts[key] = report_counts.get(key, 0) + 1

    # Convert to chart format
    intrusion_data = [intrusion_counts.get(cat, 0) for cat in categories]
    report_data = [report_counts.get(cat, 0) for cat in categories]

    return {
        "intrusions": intrusion_data,
        "reports": report_data,
        "categories": categories
    }
@router.get("/users/ChartData1", response_model=dict)
def get_chart_data(
    user_data: Annotated[dict, Depends(get_current_user)],
    period: str = "week",
    db: Session = Depends(get_db)
):
    user = db.query(User).filter_by(username=user_data["username"], id=user_data["id"]).first()
    if user is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Authentication failed.")

    current_date = datetime.now()
    days = 7 if period == "week" else 365
    categories = ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun'] if period == "week" else ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec']
    start_date = current_date - timedelta(days=days)

    if user.role == RoleEnum.admin:
        intrusions = db.query(IntrusionDetected).join(Report).filter(Report.created_at >= start_date).all()
    else:
        intrusions = db.query(IntrusionDetected).join(Report).filter(
            Report.user_id == user.id,
            Report.created_at >= start_date
        ).all()

    critical_counts = {}
    high_counts = {}
    for i in range(days):
        date = start_date + timedelta(days=i)
        key = date.strftime("%a" if period == "week" else "%b")
        critical_counts[key] = 0
        high_counts[key] = 0

    for intrusion in intrusions:
        key = intrusion.report.created_at.strftime("%a" if period == "week" else "%b")
        if intrusion.severity == 'critical':  # Adjust based on your severity values
            critical_counts[key] = critical_counts.get(key, 0) + 1
        elif intrusion.severity == 'high':
            high_counts[key] = high_counts.get(key, 0) + 1

    critical_data = [critical_counts.get(cat, 0) for cat in categories]
    high_data = [high_counts.get(cat, 0) for cat in categories]

    return {
        "critical": critical_data,
        "high": high_data,
        "categories": categories
    }

# Response model
class TransactionItem(BaseModel):
    background: str
    icon: str
    title: str
    time: str
    amount: str
    percentage: str

class TransactionResponse(BaseModel):
    transaction: List[TransactionItem]

@router.get("/users/recent-transactions", response_model=TransactionResponse)
def get_recent_transactions(
    user_data: Annotated[dict, Depends(get_current_user)],
    db: Session = Depends(get_db)
):
    user = db.query(User).filter_by(username=user_data["username"], id=user_data["id"]).first()
    if user is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Authentication failed.")

    # Construction de la requête SQL
    sql_query = text("""
        SELECT 'log' AS type, COALESCE(updated_at, created_at) AS transaction_time, file_name AS identifier
        FROM log
        WHERE :is_admin OR user_id = :user_id
        UNION ALL
        SELECT 'report' AS type, created_at AS transaction_time, title AS identifier
        FROM reports
        WHERE :is_admin OR user_id = :user_id
        ORDER BY transaction_time DESC
        LIMIT 3
    """)

    # Exécution de la requête SQL
    transactions = db.execute(sql_query, {
        "is_admin": user.role == RoleEnum.admin,
        "user_id": user.id
    }).fetchall()

    # Formatage des résultats
    result = []
    for trans_type, transaction_time, trans_id in transactions:
        time_diff = datetime.now() - transaction_time
        time_str = (f"Today, {transaction_time.strftime('%I:%M %p')}" if time_diff.days == 0 else 
                    f"{transaction_time.strftime('%d %B')}")

        is_log = trans_type == "log"
        result.append({
            "background": "text-success bg-light-success" if is_log else "text-primary bg-light-primary",
            "icon": "file" if is_log else "file-text",
            "title": f"{'Log' if is_log else 'Report'} #{trans_id}",
            "time": time_str,
            "amount": '',
            "percentage": ""  
        })

    return {"transaction": result}