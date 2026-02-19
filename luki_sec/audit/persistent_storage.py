"""
Persistent Audit Log Storage

Provides durable storage for audit logs with:
- File-based append-only logging
- JSON Lines format for easy parsing
- Automatic rotation by size and date
- Compressed archives
- Query interface for audit trail analysis
"""

import logging
import json
import gzip
from typing import Dict, Any, List, Optional
from datetime import datetime, timedelta
from pathlib import Path
from dataclasses import dataclass, asdict
import threading
from collections import deque

logger = logging.getLogger(__name__)


@dataclass
class AuditEntry:
    """Single audit log entry"""
    timestamp: str
    event_type: str
    user_id: Optional[str]
    action: str
    resource: Optional[str]
    outcome: str  # success, failure, denied
    ip_address: Optional[str]
    user_agent: Optional[str]
    details: Dict[str, Any]
    correlation_id: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return asdict(self)
    
    def to_json(self) -> str:
        """Convert to JSON string"""
        return json.dumps(self.to_dict(), separators=(',', ':'))


class PersistentAuditLogger:
    """
    Persistent audit logger with rotation and compression.
    
    Features:
    - Append-only JSON Lines format
    - Automatic file rotation
    - Compression of old logs
    - In-memory buffer for performance
    - Async write batching
    """
    
    def __init__(
        self,
        log_directory: str = "./audit_logs",
        max_file_size_mb: int = 100,
        max_age_days: int = 90,
        buffer_size: int = 1000,
        flush_interval_seconds: int = 10
    ):
        """
        Initialize persistent audit logger.
        
        Args:
            log_directory: Directory for audit log files
            max_file_size_mb: Max size before rotation
            max_age_days: Days to retain logs
            buffer_size: Number of entries to buffer before flush
            flush_interval_seconds: Max seconds between flushes
        """
        self.log_directory = Path(log_directory)
        self.max_file_size_bytes = max_file_size_mb * 1024 * 1024
        self.max_age_days = max_age_days
        self.buffer_size = buffer_size
        self.flush_interval_seconds = flush_interval_seconds
        
        # Create log directory
        self.log_directory.mkdir(parents=True, exist_ok=True)
        
        # Current log file
        self.current_file: Optional[Path] = None
        self.current_file_handle = None
        
        # In-memory buffer
        self._buffer: deque = deque(maxlen=buffer_size)
        self._lock = threading.Lock()
        self._last_flush = datetime.utcnow()
        
        # Statistics
        self.total_entries = 0
        self.total_flushes = 0
        
        # Initialize current file
        self._rotate_if_needed()
        
        logger.info(
            f"Initialized persistent audit logger",
            extra={
                "directory": str(self.log_directory),
                "max_size_mb": max_file_size_mb,
                "retention_days": max_age_days
            }
        )
    
    def log(self, entry: AuditEntry):
        """
        Log an audit entry.
        
        Args:
            entry: Audit entry to log
        """
        with self._lock:
            self._buffer.append(entry)
            self.total_entries += 1
            
            # Auto-flush if buffer is full or interval exceeded
            if (len(self._buffer) >= self.buffer_size or
                (datetime.utcnow() - self._last_flush).total_seconds() >= self.flush_interval_seconds):
                self._flush()
    
    def log_dict(
        self,
        event_type: str,
        action: str,
        outcome: str,
        user_id: Optional[str] = None,
        resource: Optional[str] = None,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
        correlation_id: Optional[str] = None
    ):
        """
        Log audit entry from individual fields.
        
        Args:
            event_type: Type of event (auth, data_access, etc.)
            action: Action performed
            outcome: Outcome (success, failure, denied)
            user_id: User identifier
            resource: Resource accessed
            ip_address: Client IP
            user_agent: User agent string
            details: Additional details
            correlation_id: Request correlation ID
        """
        entry = AuditEntry(
            timestamp=datetime.utcnow().isoformat(),
            event_type=event_type,
            user_id=user_id,
            action=action,
            resource=resource,
            outcome=outcome,
            ip_address=ip_address,
            user_agent=user_agent,
            details=details or {},
            correlation_id=correlation_id
        )
        self.log(entry)
    
    def _flush(self):
        """Flush buffer to disk"""
        if not self._buffer:
            return
        
        try:
            # Rotate file if needed
            self._rotate_if_needed()
            
            # Write buffered entries
            entries_to_write = list(self._buffer)
            self._buffer.clear()
            
            with open(self.current_file, 'a', encoding='utf-8') as f:
                for entry in entries_to_write:
                    f.write(entry.to_json() + '\n')
            
            self.total_flushes += 1
            self._last_flush = datetime.utcnow()
            
            logger.debug(
                f"Flushed {len(entries_to_write)} audit entries to {self.current_file.name}",
                extra={"entries": len(entries_to_write)}
            )
            
        except Exception as e:
            logger.error(f"Failed to flush audit logs: {e}", exc_info=True)
            # Re-add entries to buffer to avoid data loss
            self._buffer.extendleft(reversed(entries_to_write))
    
    def _rotate_if_needed(self):
        """Rotate log file if size limit exceeded"""
        # Check if current file needs rotation
        if self.current_file and self.current_file.exists():
            file_size = self.current_file.stat().st_size
            if file_size >= self.max_file_size_bytes:
                logger.info(f"Rotating audit log file (size: {file_size / 1024 / 1024:.2f} MB)")
                self._compress_current_file()
                self.current_file = None
        
        # Create new file if needed
        if self.current_file is None:
            timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
            self.current_file = self.log_directory / f"audit_{timestamp}.jsonl"
            logger.info(f"Created new audit log file: {self.current_file.name}")
        
        # Cleanup old files
        self._cleanup_old_files()
    
    def _compress_current_file(self):
        """Compress the current log file"""
        if not self.current_file or not self.current_file.exists():
            return
        
        try:
            compressed_path = self.current_file.with_suffix('.jsonl.gz')
            
            with open(self.current_file, 'rb') as f_in:
                with gzip.open(compressed_path, 'wb', compresslevel=9) as f_out:
                    f_out.writelines(f_in)
            
            # Remove uncompressed file
            self.current_file.unlink()
            
            logger.info(f"Compressed audit log to {compressed_path.name}")
            
        except Exception as e:
            logger.error(f"Failed to compress audit log: {e}", exc_info=True)
    
    def _cleanup_old_files(self):
        """Remove files older than retention period"""
        cutoff_date = datetime.utcnow() - timedelta(days=self.max_age_days)
        
        for log_file in self.log_directory.glob("audit_*.jsonl*"):
            try:
                # Extract timestamp from filename
                timestamp_str = log_file.stem.split('_', 1)[1].split('.')[0]
                file_date = datetime.strptime(timestamp_str, "%Y%m%d_%H%M%S")
                
                if file_date < cutoff_date:
                    log_file.unlink()
                    logger.info(f"Deleted old audit log: {log_file.name}")
                    
            except Exception as e:
                logger.warning(f"Error checking file {log_file.name}: {e}")
    
    def query_logs(
        self,
        start_date: Optional[datetime] = None,
        end_date: Optional[datetime] = None,
        user_id: Optional[str] = None,
        event_type: Optional[str] = None,
        outcome: Optional[str] = None,
        limit: int = 1000
    ) -> List[Dict[str, Any]]:
        """
        Query audit logs with filters.
        
        Args:
            start_date: Filter by start date
            end_date: Filter by end date
            user_id: Filter by user
            event_type: Filter by event type
            outcome: Filter by outcome
            limit: Maximum results to return
        
        Returns:
            List of matching audit entries
        """
        # Flush current buffer first
        with self._lock:
            self._flush()
        
        results = []
        
        # Query all log files
        for log_file in sorted(self.log_directory.glob("audit_*.jsonl*")):
            try:
                # Handle both compressed and uncompressed
                if log_file.suffix == '.gz':
                    open_func = gzip.open
                else:
                    open_func = open
                
                with open_func(log_file, 'rt', encoding='utf-8') as f:
                    for line in f:
                        try:
                            entry = json.loads(line.strip())
                            
                            # Apply filters
                            if start_date and entry['timestamp'] < start_date.isoformat():
                                continue
                            if end_date and entry['timestamp'] > end_date.isoformat():
                                continue
                            if user_id and entry.get('user_id') != user_id:
                                continue
                            if event_type and entry.get('event_type') != event_type:
                                continue
                            if outcome and entry.get('outcome') != outcome:
                                continue
                            
                            results.append(entry)
                            
                            if len(results) >= limit:
                                return results
                                
                        except json.JSONDecodeError:
                            logger.warning(f"Skipping invalid JSON line in {log_file.name}")
                            continue
                            
            except Exception as e:
                logger.error(f"Error reading log file {log_file.name}: {e}")
                continue
        
        return results
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get audit logger statistics"""
        total_files = len(list(self.log_directory.glob("audit_*.jsonl*")))
        total_size = sum(f.stat().st_size for f in self.log_directory.glob("audit_*.jsonl*"))
        
        return {
            "total_entries_logged": self.total_entries,
            "total_flushes": self.total_flushes,
            "buffer_size": len(self._buffer),
            "total_files": total_files,
            "total_size_mb": round(total_size / 1024 / 1024, 2),
            "current_file": self.current_file.name if self.current_file else None,
            "log_directory": str(self.log_directory)
        }
    
    def flush(self):
        """Force flush of current buffer"""
        with self._lock:
            self._flush()
    
    def close(self):
        """Close logger and flush remaining entries"""
        with self._lock:
            self._flush()
            if self.current_file_handle:
                self.current_file_handle.close()
        
        logger.info("Closed persistent audit logger")


# Global audit logger instance
_audit_logger: Optional[PersistentAuditLogger] = None


def get_audit_logger() -> PersistentAuditLogger:
    """Get the global audit logger instance"""
    global _audit_logger
    if _audit_logger is None:
        _audit_logger = PersistentAuditLogger()
    return _audit_logger
