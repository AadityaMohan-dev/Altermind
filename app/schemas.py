from datetime import datetime
from pydantic import BaseModel, ConfigDict, Field

class EventIn(BaseModel):
    event_type: str
    username: str = "unknown"
    source_ip: str = "unknown"
    process_name: str = ""
    command_line: str = ""
    message: str = ""
    timestamp: datetime | None = None

class EventOut(EventIn):
    id: int
    model_config = ConfigDict(from_attributes=True)

class CaseUpdate(BaseModel):
    status: str | None = None
    notes: str | None = None

class AssistantReview(BaseModel):
    reviewed_by: str = Field(min_length=1, max_length=100)
