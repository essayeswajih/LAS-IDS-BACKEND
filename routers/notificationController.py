import logging
from typing import List

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from db.database import get_db
from models.notification_entity import Notification
from models.usersEntity import User
from routers.auth import get_current_user
from schemas.notificationDTO import NotificationDTO


logger = logging.getLogger(__name__)

router = APIRouter(tags=["notifications"])

# GET: récupérer toutes les notifications d'un utilisateur
@router.get("/notifications", response_model=List[NotificationDTO])
def get_notifications(user_data: dict = Depends(get_current_user), db: Session = Depends(get_db)):
    try:
        user = db.query(User).filter_by(username=user_data["username"], id=user_data["id"]).first()
        if user is None:
            raise HTTPException(status_code=401, detail="Authentication failed.")
        
        notifications = db.query(Notification).filter_by(user_id=user.id).order_by(Notification.created_at).all()
        if not notifications:
            return []
        
        # Convertir en DTO
        return [NotificationDTO.model_validate(notification) for notification in notifications]
    except Exception as e:
        logger.exception("Error occurred while fetching notifications")
        raise HTTPException(status_code=500, detail="An error occurred while fetching notifications")

# POST: créer une notification
@router.post("/notification", response_model=NotificationDTO)
def create_notification(notification_data: NotificationDTO, user_data: dict = Depends(get_current_user), db: Session = Depends(get_db)):
    try:
        user = db.query(User).filter_by(username=user_data["username"], id=user_data["id"]).first()
        if user is None:
            raise HTTPException(status_code=401, detail="Authentication failed.")

        new_notification = Notification(**notification_data.model_dump(), user_id=user.id)
        
        db.add(new_notification)
        db.commit()
        db.refresh(new_notification)

        return NotificationDTO.model_validate(new_notification)
    except Exception as e:
        logger.exception("Error occurred while creating notification")
        raise HTTPException(status_code=500, detail="An error occurred while creating notification")
    
def send_notification_to_user(notification_data: NotificationDTO, user_id: int, db: Session):
    try:
        new_notification = Notification(**notification_data.model_dump(), user_id=user_id)
        
        db.add(new_notification)
        db.commit()
        db.refresh(new_notification)
        
        return NotificationDTO.model_validate(new_notification) 
    except Exception as e:
        logger.exception("Error occurred while sending notification")
        raise HTTPException(status_code=500, detail="An error occurred while sending notification")
    
def send_notifications_to_user(notifications_data: List[NotificationDTO], user_id: int, db: Session):
    try:
        new_notifications = []
        
        for notification_data in notifications_data:
            new_notification = Notification(**notification_data.model_dump(), user_id=user_id)
            db.add(new_notification)
            new_notifications.append(new_notification) 
        
        db.commit()

        for notification in new_notifications:
            db.refresh(notification)

        return [NotificationDTO.model_validate(notification) for notification in new_notifications]

    except Exception as e:
        logger.exception("Error occurred while sending notifications")
        raise HTTPException(status_code=500, detail="An error occurred while sending notifications")
    
@router.delete("/notification/{notification_id}", response_model=List[NotificationDTO])
def delete_notification(notification_id: int, user_data: dict = Depends(get_current_user), db: Session = Depends(get_db)):
    try:
        user = db.query(User).filter(User.username == user_data["username"], User.id == user_data["id"]).first()
        if user is None:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Authentication failed.")

        notification = db.query(Notification).filter(Notification.id == notification_id, Notification.user_id == user.id).first()
        if notification is None:
            raise HTTPException(status_code=404, detail="Notification not found.")

        db.delete(notification)
        db.commit()

        remaining_notifications = db.query(Notification).filter(Notification.user_id == user.id).order_by(Notification.created_at).all()
        return remaining_notifications

    except Exception as e:
        db.rollback()
        logger.exception("Error occurred while deleting notifications")
        raise HTTPException(status_code=500, detail="An error occurred while deleting notifications")

    
@router.get("/notifications_never_seen", response_model=List[NotificationDTO])
def get_notifications_sum_that_never_seen(user_data: dict = Depends(get_current_user), db: Session = Depends(get_db)):
    try:
        user = db.query(User).filter_by(username=user_data["username"], id=user_data["id"]).first()
        if user is None:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Authentication failed.")
        unseen_count = sum(1 for noti in user.notifications if noti.seen is False)
        return {"unseen_notifications": unseen_count}
    except Exception as e:
        logger.exception("Error while fetching unseen notifications count")
        raise HTTPException(status_code=500, detail="An error occurred while fetching notifications")
    

@router.get("/notification/set_seen/{notification_id}", response_model=List[NotificationDTO])
def delete_notification(notification_id: int, user_data: dict = Depends(get_current_user), db: Session = Depends(get_db)):
    try:
        user = db.query(User).filter(User.username == user_data["username"], User.id == user_data["id"]).first()
        if user is None:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Authentication failed.")

        notification = db.query(Notification).filter(Notification.id == notification_id, Notification.user_id == user.id).first()
        notification.seen = True
        if notification is None:
            raise HTTPException(status_code=404, detail="Notification not found.")

        db.add(notification)
        db.commit()

        remaining_notifications = db.query(Notification).filter(Notification.user_id == user.id).order_by(Notification.created_at).all()
        return remaining_notifications

    except Exception as e:
        db.rollback()
        logger.exception("Error occurred while deleting notifications")
        raise HTTPException(status_code=500, detail="An error occurred while deleting notifications")