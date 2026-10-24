from datetime import datetime
from pydantic import BaseModel, ConfigDict

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
