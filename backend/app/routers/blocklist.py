from typing import List
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from sqlalchemy import desc

from app.database import get_db
from app.models.db_models import BlocklistEntry
from app.schemas.schemas import ListEntryCreate, ListEntryResponse

router = APIRouter(prefix="/blocklist", tags=["Blocklist"])


@router.get("", response_model=List[ListEntryResponse])
def get_blocklist(db: Session = Depends(get_db)):
    """Retrieve all blocklist rules."""
    return db.query(BlocklistEntry).order_by(desc(BlocklistEntry.created_at)).all()


@router.post("", response_model=ListEntryResponse, status_code=status.HTTP_201_CREATED)
def add_blocklist_entry(req: ListEntryCreate, db: Session = Depends(get_db)):
    """Add a new domain or URL pattern to the blocklist."""
    pattern = req.pattern.strip().lower()
    existing = db.query(BlocklistEntry).filter(BlocklistEntry.pattern == pattern).first()
    if existing:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Pattern '{pattern}' is already in the blocklist",
        )

    entry = BlocklistEntry(
        pattern=pattern,
        entry_type=req.entry_type,
        reason=req.reason,
        added_by="manual",
    )
    db.add(entry)
    db.commit()
    db.refresh(entry)
    return entry


@router.delete("/{entry_id}", status_code=status.HTTP_204_NO_CONTENT)
def remove_blocklist_entry(entry_id: int, db: Session = Depends(get_db)):
    """Remove a rule from the blocklist by ID."""
    entry = db.query(BlocklistEntry).filter(BlocklistEntry.id == entry_id).first()
    if not entry:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Blocklist entry not found")

    db.delete(entry)
    db.commit()
    return None
