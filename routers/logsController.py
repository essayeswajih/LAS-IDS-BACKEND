import asyncio
from datetime import datetime
import hashlib
import io
import json
import subprocess
import chardet
from fastapi import APIRouter, Depends, File, Form, HTTPException, Header, Query, UploadFile, WebSocket, status
from fastapi.websockets import WebSocketState
import jwt
from pydantic import BaseModel
import pytz
from sqlalchemy import distinct, extract, func, text
from sqlalchemy.orm import Session,joinedload
from typing import Annotated, Dict, List, Optional
from models.usersEntity import RoleEnum, User
from routers.auth import ALGORITHM, SECRET_KEY, get_current_user
from routers.notificationController import send_notification_to_user
from routers.report_controller import create_report, create_report1
from schemas.Intrusion_dto import IntrusionCreateRequest, IntrusionDTO
from schemas.notificationDTO import NotificationDTO
from schemas.report_dto import ReportCreateRequest
from tools.ids import apache_error_ids, apache_ids,general_ids, windows_security_ids, syslog_ids
from tools.parser import fix_regex_pattern, parse_apache_error_log, parse_apache_log, parse_log_file, parse_nginx_error_log, parse_syslog, parse_windows_security_log
from models.rowEntity import Row
from models.logs_entity import Log
from models.report_entity import Report
from models.Intrusion_detected_entity import IntrusionDetected
from db.database import SessionLocal, get_db
from schemas.logDTO import LogDTO ,LogCreate, LogWithoutRowsDTO
from schemas.rowDTO import RowDTO
from fastapi import WebSocketDisconnect
import jwt
from jwt import ExpiredSignatureError, InvalidTokenError
import logging

#from websocket_manager.webSocketManager import WebSocketManager

logger = logging.getLogger(__name__)
#ws_manager = WebSocketManager()

router = APIRouter(tags=["logs"])

# GET: get all logs
@router.get("/logs", response_model=List[LogDTO])
def find_all_logs(db: Session = Depends(get_db)):
    try:
        logs = db.query(Log).all()
        if not logs:
            raise HTTPException(status_code=404, detail="No logs found")
        
        # Serialize logs using dict(), assuming LogDTO fields match Log model
        return logs  # Or log.to_dict() if a custom method exists
    except Exception as e:
        print(e)
        logger.error(f"Error occurred while fetching logs: {e}")
        raise HTTPException(status_code=500, detail=f"An error occurred while fetching logs: {e}")
    
# GET: get a log by ID
@router.get("/logs/{log_id}",response_model=LogWithoutRowsDTO)
def get_log_by_id(log_id:int,user_data: Annotated[dict, Depends(get_current_user)] ,db:Session =Depends(get_db)):
    user = db.query(User).filter_by(username=user_data["username"], id=user_data["id"]).first()
    if user is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Authentication failed.")
    log = db.query(Log).filter(Log.id == log_id).first()
    if log is None:
        raise HTTPException(status_code=404,detail="Log not found")
    if user.id != log.user_id:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Authentication failed.")
    return log

# POST: Create a new log
@router.post("/logs", response_model=LogCreate)
def create_log(log: LogCreate, db: Session = Depends(get_db)):
    try:
        db_log = Log(
            log_of=log.log_of,
            file_name=log.file_name,
            file_type=log.file_type
        )
        db.add(db_log)
        db.commit()
        db.refresh(db_log)
        return db_log
    except Exception as e:
        db.rollback()  # Ensure to rollback the transaction if an error occurs
        print(f"Error occurred: {e}")  # Log the exception for debugging
        raise HTTPException(
            status_code=500,
            detail="An error occurred while creating the log"
        )
    
# DELETE: delete log by id
@router.delete("/logs/{log_id}", response_model=LogDTO)
def delete_logById(log_id: int,user_data: Annotated[dict, Depends(get_current_user)], db: Session = Depends(get_db)):
    user = db.query(User).filter_by(username=user_data["username"], id=user_data["id"]).first()
    if user is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Authentication failed.")
    
    db_log = db.query(Log).filter(Log.id == log_id).first()
    
    if db_log is None:
        raise HTTPException(status_code=404, detail="Log not found")

    if user.id != db_log.user_id:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Authentication failed.")
    db.query(Row).filter(Row.log_id == db_log.id).delete()
    db.commit()
    db.delete(db_log)
    db.commit()
    
    return db_log

# POST: Upload a new Log File
@router.post("/logs/upload")
async def upload_log(user_data: Annotated[dict, Depends(get_current_user)], file: UploadFile = File(...), logOf: str = Form("Apache"),fileType: str = Form("Apache"), db: Session = Depends(get_db)):
    user = db.query(User).filter_by(username=user_data["username"], id=user_data["id"]).first()
    
    if user is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Authentication failed.")

    try:
        if not file:
            raise HTTPException(status_code=400, detail="No file uploaded.")

        # Si 'fileType' n'est pas fourni, utiliser la valeur par défaut ('Apache')
        if logOf.lower() not in ['apache', 'nginx','windows','linux']:
            raise HTTPException(status_code=400, detail="Invalid file type. Expected 'Apache' or 'Nginx' or 'Windows' or 'Linux.")
        
        if fileType.lower() not in ['access', 'error','security','syslog']:
            raise HTTPException(status_code=400, detail="Invalid file type. Expected 'Access' or 'Error' or 'Security' or 'Syslog.")

        try:
        # Lire le contenu du fichier
            contents = await file.read()
            server_hash = hashlib.sha256(contents).hexdigest()
        except:
            print("cant read file")
            raise HTTPException(status_code=400, detail="Error reading file.")
        if(fileType.lower() == 'Access'.lower()):
            row_dtos = parse_apache_log(contents.decode())
        elif( logOf.lower() == 'Apache'.lower() and fileType.lower() == 'Error'.lower()):
            row_dtos = parse_apache_error_log(contents.decode())
        elif( logOf.lower() == 'Nginx'.lower() and fileType.lower() == 'Error'.lower()):
            row_dtos = parse_nginx_error_log(contents.decode())
        elif( fileType.lower() == 'Security'.lower() ):
            row_dtos = await parse_windows_security_log(contents)
        elif( fileType.lower() == 'Syslog'.lower() ):
            row_dtos = await parse_syslog(contents.decode())
        else : raise HTTPException(status_code=400, detail="Invalid file type. Expected 'Access' or 'Error' or 'Security' or 'Syslog.")

        # Convertir les DTO en objets SQLAlchemy
        rows = [Row(**row_dto.model_dump()) for row_dto in row_dtos]
        # Get file size in bytes and convert to MB
        file_size_bytes = file.size  # Size in bytes
        file_size_mb = file_size_bytes / (1024 * 1024)  # Convert to MB (1 MB = 1,048,576 bytes)
        print("*"*20)
        print(file_size_mb)
        print("*"*20)
        # Créer et sauvegarder l'objet Log
        log = Log(
            file_name=file.filename,
            log_of=logOf,
            file_type=fileType.lower(),  # Utiliser le type de fichier envoyé ('apache' ou 'nginx')
            rows=rows,  # Associer les lignes du log
            user=user,
            file_hash=server_hash,
            rows_count=len(rows),
            size=round(file_size_mb, 4)
        )
        db.add(log)
        db.commit()
        db.refresh(log)
        log.rows = []
        # Convertir en DTO pour la réponse
        log_dto = LogDTO.model_validate(log)
        return {"message": "Log uploaded successfully", "log": log_dto.model_dump()}
    except HTTPException as he:
        raise he  # Relancer les exceptions HTTP
    except Exception as e:
        logger.error(f"Error occurred while uploading log: {e}")
        raise HTTPException(status_code=500, detail=f"An unexpected error occurred while uploading the log: {e}")
    
# POST: Upload Custom File a new Log File
@router.post("/logs/upload_custom_file")
async def upload_log(
    user_data: Annotated[dict, Depends(get_current_user)],
    file: UploadFile = File(...),
    logOf: str = Form("Any"),
    fileType: str = Form("Custom"),
    regexPattern: str = Form(""),
    db: Session = Depends(get_db)):
    user = db.query(User).filter_by(username=user_data["username"], id=user_data["id"]).first()
    
    if user is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Authentication failed.")

    try:
        if not file:
            raise HTTPException(status_code=400, detail="No file uploaded.")

        # Si 'fileType' n'est pas fourni, utiliser la valeur par défaut ('Apache')
        if logOf != "Any":
            raise HTTPException(status_code=400, detail="Invalid file type. Expected 'Any'.")
        
        if fileType not in ['Custom']:
            raise HTTPException(status_code=400, detail="Invalid file type. Expected 'Custom'.")

        try:
        # Lire le contenu du fichier
            contents = await file.read()
            server_hash = hashlib.sha256(contents).hexdigest()
        except:
            print("cant read file")
            raise HTTPException(status_code=400, detail="Error reading file.")
        if(fileType == 'Custom'):
            try:
                fixed_pattern = fix_regex_pattern(regexPattern)
                row_dtos = parse_log_file(contents.decode(), fixed_pattern)
            except:
                raise HTTPException(status_code=400, detail="Error parsing log file.")
        else : raise HTTPException(status_code=400, detail="Invalid file type. Expected 'Access' or 'Error' or 'Security' or 'Syslog.")

        # Convertir les DTO en objets SQLAlchemy
        rows = [Row(**row_dto.model_dump()) for row_dto in row_dtos]
        file_size_bytes = file.size  # Size in bytes
        file_size_mb = file_size_bytes / (1024 * 1024)  # Convert to MB (1 MB = 1,048,576 bytes)
        # Créer et sauvegarder l'objet Log
        log = Log(
            file_name=file.filename,
            log_of=logOf,
            file_type=fileType.lower(),  # Utiliser le type de fichier envoyé ('apache' ou 'nginx')
            rows=rows,  # Associer les lignes du log
            user=user,
            file_hash=server_hash,
            rows_count=len(rows),
            size=round(file_size_mb, 4)
        )
        db.add(log)
        db.commit()
        db.refresh(log)
        log.rows = []
        # Convertir en DTO pour la réponse
        log_dto = LogDTO.model_validate(log)
        return {"message": "Log uploaded successfully", "log": log_dto.model_dump()}
    except HTTPException as he:
        raise he  # Relancer les exceptions HTTP
    except Exception as e:
        logger.error(f"Error occurred while uploading log: {e}")
        raise HTTPException(status_code=500, detail=f"An unexpected error occurred while uploading the log: {e}")

# GET: get a rows by log id
@router.get("/logs/{log_id}/rows", response_model=list[RowDTO])
def find_rows_by_log_id(
    log_id: int,
    user_data: Annotated[dict, Depends(get_current_user)],
    db: Session = Depends(get_db),
    skip: int = Query(0, ge=0, description="Number of rows to skip"),
    limit: int = Query(10, le=100, description="Maximum number of rows to return")
):
    user = db.query(User).filter(User.id == user_data["id"]).first()
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Authentication failed.")

    log = db.query(Log).filter(Log.id == log_id, Log.user_id == user.id).first()
    if not log:
        raise HTTPException(status_code=404, detail="Log not found")

    rows = (
        db.query(Row)
        .filter(Row.log_id == log.id)
        .offset(skip)
        .limit(limit)
        .all()
    )

    return rows

# GET: get top status by log id
@router.get("/logs/{log_id}/topstatus", response_model=list[dict[int, int]])
def find_top_rows_by_log_id(log_id: int, db: Session = Depends(get_db)):
    log = db.query(Log).filter(Log.id == log_id).first()
    
    if log is None:
        raise HTTPException(status_code=404, detail="Log not found")
    
    # Query to get the top 5 most frequent status codes with their counts
    statuscodes = db.query(Row.status, func.count(Row.status).label('status_count')) \
        .filter(Row.log_id == log_id) \
        .group_by(Row.status) \
        .order_by(func.count(Row.status).desc()) \
        .limit(5) \
        .all()
    
    # Format the result as a list of dictionaries {status_code: count}
    top_status_codes = [{status[0]: status[1]} for status in statuscodes]
    
    return top_status_codes

# GET: get top rows that have top status by log id
@router.get("/logs/{log_id}/rows/topstatus", response_model=list[RowDTO])
def find_top_rows_by_log_id(log_id: int, db: Session = Depends(get_db)):
    log = db.query(Log).filter(Log.id == log_id).first()
    
    if log is None:
        raise HTTPException(status_code=404, detail="Log not found")
    
    # Query to get the top 5 most frequent status codes
    statuscodes = db.query(Row.status).filter(Row.log_id == log_id) \
        .group_by(Row.status) \
        .order_by(func.count(Row.status).desc()) \
        .limit(5) \
        .all()
    
    # Extract the status codes from the result
    top_status_codes = [status[0] for status in statuscodes]
    
    # Retrieve rows with those status codes and sort them
    top_rows = [row for row in log.rows if row.status in top_status_codes]
    
    return top_rows

# GET: get top status by log id
@router.get("/logs/{log_id}/toppaths", response_model=list[dict[str, int]])
def find_top_paths_by_log_id(log_id: int, db: Session = Depends(get_db)):
    log = db.query(Log).filter(Log.id == log_id).first()
    if log is None:
        raise HTTPException(status_code=404, detail="Log not found")
    
    # Query to get the top 5 most frequent paths with their counts
    paths = db.query(Row.url, func.count(Row.url).label('path_count')) \
        .filter(Row.log_id == log_id) \
        .group_by(Row.url) \
        .order_by(func.count(Row.url).desc()) \
        .limit(5) \
        .all()
    
    # Format the result as a list of dictionaries
    top_paths = [{path[0]: path[1]} for path in paths]
    
    return top_paths


# GET: get top HTTP methods by log id
@router.get("/logs/{log_id}/topmethods", response_model=list[dict[str, int]])
def find_top_methods_by_log_id(log_id: int, db: Session = Depends(get_db)):
    log = db.query(Log).filter(Log.id == log_id).first()
    if log is None:
        raise HTTPException(status_code=404, detail="Log not found")
    
    # Query to get the top 5 most frequent HTTP methods with their counts
    methods = db.query(Row.method, func.count(Row.method).label('method_count')) \
        .filter(Row.log_id == log_id) \
        .group_by(Row.method) \
        .order_by(func.count(Row.method).desc()) \
        .limit(5) \
        .all()
    
    # Format the results as a list of dictionaries
    top_methods = [{method[0]: method[1]} for method in methods]
    
    return top_methods
# GET: get top IP's methods by log id
@router.get("/logs/{log_id}/topips", response_model=list[dict[str, int]])
def find_top_ips_by_log_id(log_id: int, db: Session = Depends(get_db)):
    log = db.query(Log).filter(Log.id == log_id).first()
    if log is None:
        raise HTTPException(status_code=404, detail="Log not found")
    
    # Query to get the top 5 most frequent IP addresses with their counts
    ips = db.query(Row.ip, func.count(Row.ip).label('ip_count')) \
        .filter(Row.log_id == log_id) \
        .group_by(Row.ip) \
        .order_by(func.count(Row.ip).desc()) \
        .limit(5) \
        .all()
    
    # Format the results as a list of dictionaries
    top_ips = [{ip[0]: ip[1]} for ip in ips]
    
    return top_ips

# GET: get top protocols methods by log id
@router.get("/logs/{log_id}/topprotocols", response_model=List[Dict[str, int]])
def find_top_protocols_by_log_id(log_id: int, db: Session = Depends(get_db)):
    log = db.query(Log).filter(Log.id == log_id).first()
    if log is None:
        raise HTTPException(status_code=404, detail="Log not found")
    
    # Query to get the top 5 most frequent protocols with their counts
    protocols = db.query(Row.protocol, func.count(Row.protocol).label('protocol_count')) \
        .filter(Row.log_id == log_id, Row.protocol.isnot(None)) \
        .group_by(Row.protocol) \
        .order_by(func.count(Row.protocol).desc()) \
        .limit(5) \
        .all()

    # Format the results as a list of dictionaries
    top_protocols = []
    for protocol in protocols:
        protocol_name = protocol[0] if protocol[0] is not None else "Unknown"
        top_protocols.append({protocol_name: protocol[1]})

    return top_protocols

# GET: get top users methods by log id
@router.get("/logs/{log_id}/topusers", response_model=list[dict[str, int]])
def find_top_users_by_log_id(log_id: int, db: Session = Depends(get_db)):
    log = db.query(Log).filter(Log.id == log_id).first()
    if log is None:
        raise HTTPException(status_code=404, detail="Log not found")
    
    # Query to get the top 5 most frequent users with their counts
    users = db.query(Row.user, func.count(Row.user).label('user_count')) \
        .filter(Row.log_id == log_id) \
        .group_by(Row.user) \
        .order_by(func.count(Row.user).desc()) \
        .limit(5) \
        .all()
    
    # Format the results as a list of dictionaries
    top_users = [{user[0]: user[1]} for user in users]
    
    return top_users
# GET: get top user agents methods by log id
@router.get("/logs/{log_id}/topuseragents", response_model=list[dict[str, int]])
def find_top_user_agents_by_log_id(log_id: int, db: Session = Depends(get_db)):
    log = db.query(Log).filter(Log.id == log_id).first()
    if log is None:
        raise HTTPException(status_code=404, detail="Log not found")
    
    # Query to get the top 5 most frequent user agents with their counts
    user_agents = db.query(Row.user_agent, func.count(Row.user_agent).label('user_agent_count')) \
        .filter(Row.log_id == log_id) \
        .group_by(Row.user_agent) \
        .order_by(func.count(Row.user_agent).desc()) \
        .limit(5) \
        .all()
    
    # Format the results as a list of dictionaries
    top_user_agents = [{user_agent[0]: user_agent[1]} for user_agent in user_agents]
    
    return top_user_agents


class FilterRequest(BaseModel):
    file_name: str
    sed_command: str

# POST: get filtred rows by log name and sed command
@router.post("/logs/rows/filtred", response_model=str)
def find_filtred_rows_by_log_name_and_sed_command(
    request: FilterRequest,  # Use the request body model
    db: Session = Depends(get_db)
):
    file_name = request.file_name
    sed_command = request.sed_command

    # Fetch the log by file name
    log = db.query(Log).filter(Log.file_name == file_name).first()
    if not log:
        raise HTTPException(status_code=404, detail="Log not found")

    # Check if the log has rows
    if not log.rows:
        raise HTTPException(status_code=400, detail="No rows found for the log")

    # Convert rows to a formatted string suitable for sed processing
    try:
        rows_data = "\n".join(
            f"{row.ip} {row.remote_logname} {row.user} {row.timestamp} "
            f"{row.method} {row.url} {row.protocol} {row.status} "
            f"{row.response_size if row.response_size else '0'} {row.referer if row.referer else '-'} {row.user_agent}"
            for row in log.rows
        )
    except AttributeError as e:
        raise HTTPException(status_code=500, detail=f"Error formatting rows: {e} , {(log.rows[0])}")

    try:
        # Use subprocess to apply the sed command on rows_data
        process = subprocess.run(
            ["sed", sed_command],
            input=rows_data,
            text=True,
            capture_output=True,
            check=True,
        )
        filtered_output = process.stdout

        return filtered_output

    except subprocess.CalledProcessError as e:
        raise HTTPException(
            status_code=400,
            detail=f"Error applying sed command: {e.stderr or str(e)}"
        )
    
# GET: Get recent rows across all logs for the user
@router.get("/logs/get/recentrows", response_model=List[RowDTO])
def find_recent_rows(
    user_data: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    # Authentifier l'utilisateur
    user = db.query(User).filter_by(username=user_data["username"], id=user_data["id"]).first()
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Authentication failed.")

    # Construire la requête pour récupérer les lignes récentes
    query = db.query(Row).join(Log, Row.log_id == Log.id)

    if user.role != RoleEnum.admin:
        query = query.filter(Log.user_id == user.id)

    rows = query.order_by(Row.id.desc()).limit(10).all()

    return rows if rows else []


# GET: get total Page Views statistics
@router.get("/logs/{log_id}/totalpageviews", response_model=dict[str, int])
def find_total_page_views_by_log_id(log_id: int, db: Session = Depends(get_db)):
    log = db.query(Log).filter(Log.id == log_id).first()
    if log is None:
        raise HTTPException(status_code=404, detail="Log not found")
    
    total_page_views = db.query(func.count(Row.id)) \
        .filter(Row.log_id == log_id) \
        .scalar()
    
    current_month = datetime.now().month

    total_page_views_this_month = db.query(func.count(Row.id)) \
        .filter(Row.log_id == log_id) \
        .filter(
            func.extract('month', func.to_timestamp(Row.timestamp, 'DD/Mon/YYYY:HH24:MI:SS +0000')) == current_month
        ) \
        .scalar()
    
    total_page_views_last_month = db.query(func.count(Row.id)) \
        .filter(Row.log_id == log_id) \
        .filter(
            func.extract('month', func.to_timestamp(Row.timestamp, 'DD/Mon/YYYY:HH24:MI:SS +0000')) == current_month - 1
        ) \
        .scalar()

    total_page_views_this_year = db.query(func.count(Row.id)) \
        .filter(Row.log_id == log_id) \
        .filter(
            func.extract('year', func.to_timestamp(Row.timestamp, 'DD/Mon/YYYY:HH24:MI:SS +0000')) == datetime.now().year
        ) \
        .scalar()
    total_page_views_last_year = db.query(func.count(Row.id)) \
        .filter(Row.log_id == log_id) \
        .filter(
            func.extract('year', func.to_timestamp(Row.timestamp, 'DD/Mon/YYYY:HH24:MI:SS +0000')) == datetime.now().year - 1
        ) \
        .scalar()
    return {
        "total_views":total_page_views,
        "total_views_this_month":total_page_views_this_month,
        "total_views_last_month":total_page_views_last_month,
        "total_views_this_year":total_page_views_this_year,
        "total_views_last_year":total_page_views_last_year,
        }

# GET: get total Request Statistics
@router.get("/logs/{log_id}/totalrequests", response_model=dict)
def find_total_page_views_by_log_id(log_id: int, db: Session = Depends(get_db)):
    log = db.query(Log).filter(Log.id == log_id).first()
    if log is None:
        raise HTTPException(status_code=404, detail="Log not found")

    # Total page views
    total_page_views = db.query(func.count(Row.id)).filter(Row.log_id == log_id).scalar()

    # Get current month and year
    now = datetime.now()
    current_month = now.month
    current_year = now.year

    # Handle last month calculation
    last_month = (current_month - 1) if current_month > 1 else 12
    last_month_year = current_year if current_month > 1 else current_year - 1

    # Total page views for this month
    total_page_views_this_month = db.query(func.count(Row.id)) \
        .filter(Row.log_id == log_id) \
        .filter(func.extract('month', func.to_timestamp(Row.timestamp, 'DD/Mon/YYYY:HH24:MI:SS +0000')) == current_month) \
        .scalar()

    # Total page views for last month
    total_page_views_last_month = db.query(func.count(Row.id)) \
        .filter(Row.log_id == log_id) \
        .filter(func.extract('month', func.to_timestamp(Row.timestamp, 'DD/Mon/YYYY:HH24:MI:SS +0000')) == last_month) \
        .filter(func.extract('year', func.to_timestamp(Row.timestamp, 'DD/Mon/YYYY:HH24:MI:SS +0000')) == last_month_year) \
        .scalar()

    # Total page views for this year
    total_page_views_this_year = db.query(func.count(Row.id)) \
        .filter(Row.log_id == log_id) \
        .filter(func.extract('year', func.to_timestamp(Row.timestamp, 'DD/Mon/YYYY:HH24:MI:SS +0000')) == current_year) \
        .scalar()

    # Total page views for last year
    total_page_views_last_year = db.query(func.count(Row.id)) \
        .filter(Row.log_id == log_id) \
        .filter(func.extract('year', func.to_timestamp(Row.timestamp, 'DD/Mon/YYYY:HH24:MI:SS +0000')) == current_year - 1) \
        .scalar()

    # Calculate percentages
    month_percentage = calculate_percentage(total_page_views_last_month, total_page_views_this_month)
    year_percentage = calculate_percentage(total_page_views_last_year, total_page_views_this_year)

    return {
        "total_requests": total_page_views,
        "total_requests_this_month": total_page_views_this_month,
        "total_requests_last_month": total_page_views_last_month,
        "month_percentage": month_percentage,
        "total_requests_this_year": total_page_views_this_year,
        "total_requests_last_year": total_page_views_last_year,
        "year_percentage": year_percentage
    }
        

# GET: get total Request Failed statistics
@router.get("/logs/{log_id}/totalrequestfailed", response_model=dict[str, int])
def find_total_request_failed_by_log_id(log_id: int, db: Session = Depends(get_db)):
    log = db.query(Log).filter(Log.id == log_id).first()
    if log is None:
        raise HTTPException(status_code=404, detail="Log not found")
    
    total_request_failed = db.query(func.count(Row.id)) \
        .filter(Row.log_id == log_id) \
        .filter(Row.status != 200 or Row.status != 201) \
        .scalar()

    total_request_failed_this_month = db.query(func.count(Row.id)) \
        .filter(Row.log_id == log_id) \
        .filter(Row.status != 200 or Row.status != 201) \
        .filter(
            func.extract('month', func.to_timestamp(Row.timestamp, 'DD/Mon/YYYY:HH24:MI:SS +0000')) == datetime.now().month
        )\
        .scalar()
    
    total_request_failed_last_month = db.query(func.count(Row.id)) \
        .filter(Row.log_id == log_id) \
        .filter(Row.status != 200 or Row.status != 201) \
        .filter(
            func.extract('month', func.to_timestamp(Row.timestamp, 'DD/Mon/YYYY:HH24:MI:SS +0000')) == datetime.now().month - 1
        )\
        .scalar()
    
    total_request_failed_this_year = db.query(func.count(Row.id)) \
        .filter(Row.log_id == log_id) \
        .filter(Row.status != 200 or Row.status != 201) \
        .filter(
            func.extract('year', func.to_timestamp(Row.timestamp, 'DD/Mon/YYYY:HH24:MI:SS +0000')) == datetime.now().year
        )\
        .scalar()
    
    total_request_failed_last_year = db.query(func.count(Row.id)) \
        .filter(Row.log_id == log_id) \
        .filter(Row.status != 200 or Row.status != 201) \
        .filter(
            func.extract('year', func.to_timestamp(Row.timestamp, 'DD/Mon/YYYY:HH24:MI:SS +0000')) == datetime.now().year - 1
        )\
        .scalar()
    # fall or rise percentage on month 
    month_percentage = calculate_percentage(total_request_failed_last_month, total_request_failed_this_month)
    # fall or rise percentage on year
    year_percentage = calculate_percentage(total_request_failed_last_year, total_request_failed_this_year)
    return {
        "total_request_failed":total_request_failed,
        "total_request_failed_this_month":total_request_failed_this_month,
        "total_request_failed_last_month":total_request_failed_last_month,
        "month_percentage":month_percentage,
        "total_request_failed_this_year":total_request_failed_this_year,
        "total_request_failed_last_year":total_request_failed_last_year,
        "year_percentage":year_percentage
        }
    
def calculate_percentage(last_value, current_value):
    if last_value == 0:
        if current_value > 0:
            return "New activity"  # Indicates an increase from zero
        return "No activity"  # Indicates no activity in both periods
    if current_value == 0:
        return -100  # Explicitly indicate a 100% decrease
    try:
        return ((current_value - last_value) / last_value) * 100
    except ZeroDivisionError:
        return "Error"  # Fallback for unexpected errors



# GET: get total Users statistics
@router.get("/logs/{log_id}/totalusers", response_model=dict[str, int])
def find_total_users_by_log_id(log_id: int, db: Session = Depends(get_db)):
    log = db.query(Log).filter(Log.id == log_id).first()
    if log is None:
        raise HTTPException(status_code=404, detail="Log not found")
    
    total_users = db.query(func.count(distinct(Row.ip))) \
                    .filter(Row.log_id == log_id) \
                    .scalar()
        
    return {"total_users":total_users}

# GET: get this week requests overview
@router.get("/logs/{log_id}/weekoverview", response_model=dict)
def find_week_overview_by_log_id(log_id: int, db: Session = Depends(get_db)):
    # Check if log exists
    log = db.query(Log).filter(Log.id == log_id).first()
    if log is None:
        raise HTTPException(status_code=404, detail="Log not found")
    try:
    
        # Current year and week
        current_year = datetime.now().year   # Adjust year if needed
        current_week = datetime.now().isocalendar()[1]

        # Query for request counts grouped by day of the week
        try:
            results = db.query(
                func.extract('dow', func.to_timestamp(Row.timestamp, 'DD/Mon/YYYY:HH24:MI:SS')).label('dow'),
                func.count(Row.id).label('count')
            ) \
            .filter(Row.log_id == log_id) \
            .filter(
                func.extract('year', func.to_timestamp(Row.timestamp, 'DD/Mon/YYYY:HH24:MI:SS')) == current_year
            ) \
            .filter(
                func.extract('week', func.to_timestamp(Row.timestamp, 'DD/Mon/YYYY:HH24:MI:SS')) == current_week
            ) \
            .group_by(
                func.extract('dow', func.to_timestamp(Row.timestamp, 'DD/Mon/YYYY:HH24:MI:SS'))
            ) \
            .order_by(
                func.extract('dow', func.to_timestamp(Row.timestamp, 'DD/Mon/YYYY:HH24:MI:SS'))
            ) \
            .all()

            # Log results for debugging
            print(results)

            # Map days of the week (0=Sunday, 1=Monday, ..., 6=Saturday)
            day_mapping = {0: 'Su', 1: 'Mo', 2: 'Tu', 3: 'We', 4: 'Th', 5: 'Fr', 6: 'Sa'}
            counts = {day: 0 for day in day_mapping.values()}  # Initialize counts for all days
            
            # Populate counts based on the query results
            for result in results:
                day = day_mapping.get(result.dow, None)
                if day:
                    counts[day] = result.count

            # List of days in order
            days = ['Su', 'Mo', 'Tu', 'We', 'Th', 'Fr', 'Sa']
            
            return {"days": days, "counts": [counts[day] for day in days]}
        except:
            raise HTTPException(status_code=500, detail=f"An error occurred: {str(e)}")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"An error occurred: {str(e)}")

# Define Pydantic request model
class FilterRequest(BaseModel):
    id: int
    statusOption: str
    statusValue: str
    ipsOption: str
    ipsValue: Optional[str] = None
    methodOption: str
    methodValue: str
    pathOption: str
    pathValue: Optional[str] = None
    requestOption: str
    requestValue: Optional[str] = None
    userAgentOption: str
    userAgentValue: Optional[str] = None
    referrerOption: str
    referrerValue: Optional[str] = None
    moduleOption: str
    moduleValue: Optional[str] = None
    levelOption: str
    levelValue: Optional[str] = None
    messageOption: str
    messageValue: Optional[str] = None
    pidOption: str
    pidValue: Optional[str] = None
    tidOption: str
    tidValue: Optional[str] = None

@router.post("/logs/simpleApacheAccessLogFilter", response_model=List[RowDTO])
async def simple_apache_access_log_filter(
    request: FilterRequest,
    user_data: dict = Depends(get_current_user),
    db: Session = Depends(get_db),
    skip: int = Query(0, ge=0, description="Nombre de lignes à ignorer"),
    limit: int = Query(10, le=100, description="Nombre maximal de lignes à retourner")
):
    # Validation de l'utilisateur
    user = db.query(User).filter(User.id == user_data["id"]).first()
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Authentication failed.")

    # Validation du fichier de logs
    log_file = db.query(Log).filter(Log.id == request.id).first()
    if not log_file:
        raise HTTPException(status_code=404, detail="Log not found")
    if user.id != log_file.user_id:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Unauthorized access")

    # Base query
    query = "SELECT * FROM row WHERE log_id = :log_id"
    conditions = []
    params = {"log_id": log_file.id, "limit": limit, "skip": skip}

    # Filtrage du statut HTTP
    status_ranges = {
        "1xx": (100, 199), "2xx": (200, 299), "3xx": (300, 399),
        "4xx": (400, 499), "5xx": (500, 599),
    }

    if request.statusOption in ["Include", "Exclude"] and request.statusValue in status_ranges:
        operator = "BETWEEN" if request.statusOption == "Include" else "NOT BETWEEN"
        conditions.append(f"status {operator} :status_min AND :status_max")
        params.update({"status_min": status_ranges[request.statusValue][0],
                       "status_max": status_ranges[request.statusValue][1]})

    # Fonction pour appliquer les filtres LIKE, NOT LIKE et Regex
    def add_filter(field: str, option: str, value: str):
        filters = {
            "Include": f"{field} LIKE :{field}_value",
            "Exclude": f"{field} NOT LIKE :{field}_value",
            "Include (Regex)": f"{field} ~ :{field}_regex",
            "Exclude (Regex)": f"{field} !~ :{field}_regex",
        }
        if option in filters and value:
            conditions.append(filters[option])
            params[f"{field}_regex" if "Regex" in option else f"{field}_value"] = f"%{value}%" if "Regex" not in option else value

    # Appliquer les filtres aux champs pertinents
    for field, option, value in [
        ("ip", request.ipsOption, request.ipsValue),
        ("url", request.pathOption, request.pathValue),
        ("request", request.requestOption, request.requestValue),
        ("user_agent", request.userAgentOption, request.userAgentValue),
        ("referrer", request.referrerOption, request.referrerValue),
        ("module", request.moduleOption, request.moduleValue.lower() if request.moduleValue else None),
        ("level", request.levelOption, request.levelValue.lower() if request.levelValue else None),
        ("message", request.messageOption, request.messageValue),
        ("pid", request.pidOption, request.pidValue),
        ("tid", request.tidOption, request.tidValue),
    ]:
        if value:
            if "Unique" in option:
                conditions.append(f"{field} = :{field}")
                params[field] = value
            else:
                add_filter(field, option, value)

    # Liste des méthodes HTTP standards
    http_methods = ['GET', 'POST', 'PUT', 'DELETE', 'HEAD', 'OPTIONS', 'TRACE']

    # Filtrage de la méthode HTTP
    if request.methodValue and request.methodValue != "All":
        if request.methodOption == "Others":
            conditions.append("method NOT IN :methods_list")
            params["methods_list"] = tuple(http_methods)
        else:
            operator = "=" if request.methodOption == "Include" else "!="
            conditions.append(f"method {operator} :method")
            params["method"] = request.methodValue

    # Finalisation de la requête SQL
    if conditions:
        query += " AND " + " AND ".join(conditions)
    # Ajout de la pagination
    query += " ORDER BY id LIMIT :limit OFFSET :skip"

    print(query)  # Debugging

    # Exécution de la requête
    result = db.execute(text(query), params).mappings().all()
    return [RowDTO(**row) for row in result]

def get_jwt_token(token: str):
    try:
        # Remove the "Bearer " prefix from the token if present
        token = token.replace("Bearer ", "")

        # Decode the token
        payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])

        # Return the payload if the token is valid
        return payload

    except ExpiredSignatureError:
        raise Exception("JWT token has expired.")
    except InvalidTokenError:
        raise Exception("Invalid JWT token.")
    except Exception as e:
        raise Exception(f"Failed to decode JWT token: {e}")

class ConnectionManager:
    def __init__(self):
        self.rooms: Dict[str, List[WebSocket]] = {}

    async def connect(self, websocket: WebSocket, room: str):
        await websocket.accept()
        if room not in self.rooms:
            self.rooms[room] = []
        self.rooms[room].append(websocket)

    def disconnect(self, websocket: WebSocket, room: str):
        if room in self.rooms:
            self.rooms[room].remove(websocket)
            if not self.rooms[room]:  # Remove room if empty
                del self.rooms[room]

    async def broadcast(self, message: str, room: str):
        if room in self.rooms:
            for connection in self.rooms[room]:
                await connection.send_text(message)

    async def broadcast_json(self, message: dict, room: str):
        if room in self.rooms:
            for connection in self.rooms[room]:
                await connection.send_json(message)

manager = ConnectionManager()

@router.websocket("/ws/{token}")
async def websocket_endpoint(websocket: WebSocket, token: str):
    db = SessionLocal()
    try:
        user = await get_user_from_token(token, db)
        if user is None:
            await websocket.close(code=4000)
            return

        room = user.room_name

        # ✅ Accept should happen only once, inside manager.connect
        await manager.connect(websocket, room)

        try:
            while True:
                data = await websocket.receive_text()
                newdata = await update_log(user, data, room, websocket, db)
                await manager.broadcast_json({
                    "type": "message",
                    "data": f"📢 Message from {room}: {newdata}"
                }, room)
        except WebSocketDisconnect:
            manager.disconnect(websocket, room)
    finally:
        db.close()

async def get_user_from_token(token: str, db: Session) -> Optional[User]:
    """ Validate token and return the user object """
    try:
        payload = get_jwt_token(token)
        user_id = payload.get("id")
        user_name = payload.get("sub")

        if not user_id or not user_name:
            raise ValueError("Invalid token: Missing user information")

        user = db.query(User).filter_by(id=user_id, username=user_name).first()
        if not user:
            return None

        return user

    except Exception as e:
        print(f"⚠️ Token validation or user lookup failed: {e}")
        return None

async def update_log(user: User, log_data: str, room: str, websocket: WebSocket, db: Session):
    """ Processes log data, validates the user, and updates the database. """
    try:
        if not isinstance(log_data, str):
            await websocket.send_text("Error: Invalid log data format")
            return "Error: Invalid log data format"

        first_newline = log_data.find('\\n')
        if first_newline == -1:
            await websocket.send_text("Error: Invalid data format (newline required)")
            return "Error: Invalid data format"

        first_row = log_data[:first_newline].strip()
        filename, file_of, file_type = first_row.split(",")
        log_rows = log_data[first_newline + 1:].strip()
        server_hash = hashlib.sha256(log_rows.encode('utf-8')).hexdigest()
        print(filename)
        print(file_of)
        print(file_type)

        if not log_rows:
            return "Error: Log data is empty"

        # Parse logs
        rows = None  # Initialize rows
        f = db.query(Log).filter_by(file_name=filename).first()
        if f:
            file_of = f.log_of
            file_type = f.file_type
        
        # Assign rows based on file_type
        if file_type.lower() == 'access':
            rows = parse_apache_log(log_rows)
        elif file_type.lower() == 'error':
            rows = parse_apache_error_log(log_rows)
        elif file_type.lower() == 'security':
            rows = parse_windows_security_log(log_rows)
        elif file_type.lower() == 'syslog':
            rows = parse_syslog(log_rows)
        else:
            await websocket.send_text("Error: Unsupported file type")
            return f"Error: Unsupported file type - {file_type}"

        # Validate parsed rows
        if not rows:
            raise ValueError("No valid log entries found")

        lastupdatedDate = None
        try:
            # Get last file updated time
            lastupdatedDate = f.updated_at if f and f.updated_at else f.created_at if f else None
        except Exception as e:
            print(f"Warning: Could not get last file update time - {e}")
            return "Error: Can't get last file update time"

        lastrows = getlastRows(lastupdatedDate, rows)
        
        # Convert rows to row_models before proceeding (moved up from inside if block)
        row_models = [Row(**row_dto.model_dump()) for row_dto in rows]

        # Update or create log entry regardless of new rows
        log = db.query(Log).filter(Log.user_id == user.id, Log.file_name == filename).first()
        size = len(log_rows.encode('utf-8'))  # Size in bytes
        size_mb = size / (1024 * 1024)  # Convert to megabytes
        if log:
            db.query(Row).filter(Row.log_id == log.id).delete()
            db.commit()
            log.rows = row_models
            log.file_hash = server_hash
            log.rows_count = len(row_models)
            log.size = round(size_mb, 1)
            log.updated_at = func.now()
            print("📝 Log file updated.")
        else:
            log = Log(
                file_name=filename,
                log_of=file_of,
                file_type=file_type,
                rows=row_models,
                user=user,
                file_hash=server_hash,
                rows_count=len(row_models),
                size=round(size_mb, 4)
            )
            db.add(log)
            print("📂 New log file created.")

        db.commit()
        db.refresh(log)

        # Check for new rows and handle notifications/reports
        print(len(lastrows))
        if len(lastrows) > 0:
            intrusions = detect(file_type, lastrows)
            noti_dto = NotificationDTO(
                title="Report generated for " + filename,
                message="Report generated for " + filename,
                icon="Alert",
                details="Suspicious activity report for " + filename + " at " + str(func.now())
            )
            noti_dto1 = NotificationDTO(
                title=str(len(intrusions)) + " Intrusion Detected for " + filename,
                message=str(len(intrusions)) + " Intrusion Detected for " + filename,
                icon="Alert",
                details=str(len(intrusions))+" Suspicious activity detected for " + filename + " at " + str(func.now())
            )
            send_notification_to_user(noti_dto, user.id, db)
            send_notification_to_user(noti_dto1, user.id, db)
            new_report = ReportCreateRequest(
                intrusions=intrusions,
                title=filename + " report",
                description="Suspicious activity report"
            )
            await create_report1(request=new_report, db=db, user=user)
            await manager.broadcast_json({"type": "intrusions", "data": apache_ids(lastrows)}, room)
            return f"✅ Log updated: {filename}"
        else:
            return f"{filename} is already updated ✅"

    except Exception as e:
        print(f"❌ Log parsing failed: {e}")
        return f"Error: Log parsing failed - {e}"

@router.get("/logs/file-hash/{filename}", response_model=dict)
async def get_file_hash(
    filename: str,
    user_data: dict = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    print(f"Received filename: '{filename}'")

    user = db.query(User).filter_by(username=user_data["username"], id=user_data["id"]).first()
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Authentication failed.")
    
    if not filename:
        raise HTTPException(status_code=400, detail="Filename is required")
    file = db.query(Log).filter(Log.file_name == filename, Log.user_id == user.id).first()
    if not file:
        raise HTTPException(status_code=404, detail=f"File '{filename}' not found")
    return {"hash": file.file_hash}

def getlastRows(last_datetime: Optional[datetime], rows: List[RowDTO]) -> List[RowDTO]:
    try:
        if last_datetime is None:
            return rows
        apache_format = "%d/%b/%Y:%H:%M:%S %z"
        last_datetime = datetime.strptime(rows[0].timestamp, apache_format)
    except ValueError:
        last_datetime = None
        return rows
    # Assume UTC for last_datetime if naive
    if last_datetime.tzinfo is None:
        last_datetime = pytz.UTC.localize(last_datetime)
    apache_format = "%d/%b/%Y:%H:%M:%S %z"
    return [row for row in rows if datetime.strptime(row.timestamp, apache_format) >= last_datetime]

@router.get("/logs/detect-intrusions/{fileId}", response_model=dict)
async def get_report(
    fileId: int,
    user_data: dict = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    user = db.query(User).filter_by(username=user_data["username"], id=user_data["id"]).first()
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Authentication failed.")
    
    if not fileId:
        raise HTTPException(status_code=400, detail="Filename is required")
    if user.role == RoleEnum.admin:
        file = db.query(Log).filter(Log.id == fileId).first()
    else:
        file = db.query(Log).filter(Log.id == fileId, Log.user_id == user.id).first()
    if not file:
        raise HTTPException(status_code=404, detail=f"File not found")
    intrusions = []
    try:
        intrusions = detect(file.file_type,file.rows)
        new_report = ReportCreateRequest(intrusions=intrusions,title=file.file_name + " Intrusion Report",description=f"Analysis of {file.file_type} logs for potential security incidents")
        data = await create_report1(request=new_report,db=db,user=user)
        return {"message":"report created for "+file.file_name,"data":data}
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"Detection failed.{e}")

def detect(file_type: str, rows: List[RowDTO]) -> List[IntrusionCreateRequest]:
    intrusions = []  # Initialize empty list for IntrusionCreateRequest objects
    
    match file_type.lower():
        case "access":
            for intrusion in apache_ids(rows):
                title = ", ".join(intrusion['detected_attacks'])
                m = (f"[{intrusion['timestamp']}] 🚨 Suspicious activity from {intrusion['ip']} on {intrusion['url']} ({intrusion['method']}):")
                intrusions.append(IntrusionCreateRequest(detected_attack=title, description=m, severity=intrusion["severity_level"]))
        case "error":
            for intrusion in apache_error_ids(rows):
                title = ", ".join(intrusion['detected_attacks'])
                m = (
                    f"[{intrusion['timestamp']}] 🚨 Error log anomaly detected from {intrusion['ip']} "
                    f"[{intrusion.get('level', 'N/A')}] in module {intrusion.get('module', 'N/A')}: {intrusion['message']}"
                )
                intrusions.append(IntrusionCreateRequest(detected_attack=title, description=m, severity=intrusion["severity_level"]))
        case "security":
            for intrusion in windows_security_ids(rows):
                title = ", ".join(intrusion['detected_attacks'])
                m = (f"[{intrusion['timestamp']}] 🚨 Security event detected from {intrusion['ip']} affecting {intrusion.get('url', 'N/A')}:")
                intrusions.append(IntrusionCreateRequest(detected_attack=title, description=m, severity=intrusion["severity_level"]))
        case "syslog":
            for intrusion in syslog_ids(rows):
                title = ", ".join(intrusion['detected_attacks'])
                m = (f"[{intrusion['timestamp']}] 🚨 System log anomaly detected from {intrusion['ip']} affecting {intrusion.get('url', 'N/A')}:")
                intrusions.append(IntrusionCreateRequest(detected_attack=title, description=m, severity=intrusion["severity_level"]))
        case _:
            for intrusion in general_ids(rows):
                title = ", ".join(intrusion['detected_attacks'])
                m = (
                    f"[{intrusion['timestamp']}] 🚨 Potential threat detected from {intrusion['ip']} "
                    f"by {intrusion.get('user_info', 'Unknown') }user in {intrusion.get('component', 'N/A')} "
                    f"(Event: {intrusion.get('event_id', 'N/A')}): {intrusion['message']}"
                )
                intrusions.append(IntrusionCreateRequest(detected_attack=title, description=m, severity=intrusion["severity_level"]))
    
    return intrusions
    