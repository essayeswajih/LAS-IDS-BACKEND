from datetime import datetime
import logging
from typing import Annotated, List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel
from sqlalchemy import func
from sqlalchemy.orm import Session, joinedload, aliased

from db.database import get_db
from models.Intrusion_detected_entity import IntrusionDetected
from models.report_entity import Report
from models.usersEntity import RoleEnum, User
from routers.auth import get_current_user
from schemas.Intrusion_dto import IntrusionDTO
from schemas.report_dto import ReporLitetDTO, ReportCreateRequest, ReportDTO  # Assuming DTOs exist

logger = logging.getLogger(__name__)

router = APIRouter(tags=["reports"])

@router.get("", response_model=List[ReporLitetDTO])
def find_all_reports(
    user_data: Annotated[dict, Depends(get_current_user)],
    db: Session = Depends(get_db),
    page: int = Query(1, ge=1),
    size: int = Query(10, ge=1)
):
    user = db.query(User).filter_by(username=user_data["username"], id=user_data["id"]).first()

    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication failed."
        )

    # Join Report with IntrusionDetected (aliased if needed)
    intrusion_alias = aliased(IntrusionDetected)

    query = (
        db.query(
            Report,
            func.count(intrusion_alias.id).label("intrusion_count")
        )
        .outerjoin(intrusion_alias, intrusion_alias.report_id == Report.id)
        .group_by(Report.id).order_by(Report.created_at)
    )

    if user.role != RoleEnum.admin:
        query = query.filter(Report.user_id == user.id)

    results = query.offset((page - 1) * size).limit(size).all()

    if not results:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="No reports found."
        )

    report_dtos = []
    for report, intrusion_count in results:
        dto = ReporLitetDTO.model_validate(report)
        dto.intrusion_count = intrusion_count
        report_dtos.append(dto)

    return report_dtos

# POST: Create a new report
@router.post("", response_model=ReportDTO, status_code=status.HTTP_201_CREATED)
async def create_report(
    request: ReportCreateRequest,
    user_data: Annotated[dict, Depends(get_current_user)],
    db: Session = Depends(get_db),
):
    # Verify user authentication
    user = db.query(User).filter_by(username=user_data["username"], id=user_data["id"]).first()
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication failed."
        )

    # Call the async function and return its result
    return await create_report1(request, db, user)

async def create_report1(
    request: ReportCreateRequest,
    db: Session,
    user: User
) -> ReportDTO:
    new_report = Report(
        title=request.title,
        description=request.description,
        user_id=user.id
    )
    
    db.add(new_report)
    db.flush()  # Ensure the report ID is generated before adding intrusions

    # Save all associated intrusions
    intrusion_objects = [
        IntrusionDetected(
            description=intrusion.description,
            detected_attack=intrusion.detected_attack,
            severity=intrusion.severity,
            report_id=new_report.id,
        )
        for intrusion in request.intrusions
    ]

    db.add_all(intrusion_objects)
    db.commit()
    db.refresh(new_report)

    return ReportDTO(
        title=new_report.title,
        description=new_report.description,
        intrusions=[
            IntrusionDTO(
                id=intrusion.id,
                description=intrusion.description,
                detected_attack=intrusion.detected_attack,
                severity=intrusion.severity,
                timestamp=intrusion.timestamp,
                report_id=new_report.id
            )
            for intrusion in intrusion_objects
        ]
    )

class PaginatedIntrusions(BaseModel):
    intrusions: List[IntrusionDTO]
    total: int
    page: int
    page_size: int
    total_pages: int
    
@router.get("/{report_id}/intrusions", response_model=PaginatedIntrusions)
async def get_intrusions_by_report_id(
    report_id: int,
    user_data: Annotated[dict, Depends(get_current_user)],
    db: Session = Depends(get_db),
    page: int = Query(1, ge=1),   # Page number (default: 1, must be >= 1)
    size: int = Query(10, ge=1)   # Page size (default: 10, must be >= 1)
):
    # Verify user authentication
    user = db.query(User).filter_by(username=user_data["username"], id=user_data["id"]).first()
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication failed."
        )

    # Check if report exists and user has permission
    report = db.query(Report).filter(Report.id == report_id).first()
    if not report:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Report not found."
        )
    if report.user_id != user.id and user.role != RoleEnum.admin:  # Allow admins to view all
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="You do not have permission to view intrusions for this report."
        )

    # Query IntrusionDetected directly for total count and pagination
    query = db.query(IntrusionDetected).filter(IntrusionDetected.report_id == report_id)
    total = query.count()  # Get total count from the database
    print("count",total)
    # Apply pagination
    intrusions = query.offset((page - 1) * size).limit(size).all()
    
    # Calculate total pages
    total_pages = (total + size - 1) // size  # Ceiling division

    # Return paginated response
    return {
        "intrusions": [
            IntrusionDTO(
                id=intrusion.id,
                description=intrusion.description,
                detected_attack=intrusion.detected_attack,
                severity=intrusion.severity,
                timestamp=intrusion.timestamp,
                report_id=intrusion.report_id
            )
            for intrusion in intrusions
        ],
        "total": total,
        "page": page,
        "page_size": size,
        "total_pages": total_pages
    }

# DELETE: Delete a report by ID
@router.delete("/{report_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_report(
    report_id: int,
    user_data: Annotated[dict, Depends(get_current_user)],
    db: Session = Depends(get_db)
):
    user = db.query(User).filter_by(username=user_data["username"], id=user_data["id"]).first()

    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication failed."
        )

    report = db.query(Report).filter_by(id=report_id).first()

    if not report:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Report not found."
        )

    if user.role != RoleEnum.admin and report.user_id != user.id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="You do not have permission to delete this report."
        )

    # Delete related intrusions_detected rows first
    db.query(IntrusionDetected).filter_by(report_id=report_id).delete()
    db.delete(report)
    db.commit()

    return {"message": "Report deleted successfully"}