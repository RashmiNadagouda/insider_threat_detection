from collections import Counter
from typing import List

from app.schemas.event import ActivityEvent


def extract_features(events: List[ActivityEvent]) -> dict:
    """
    Convert ActivityEvent objects into a behavioral
    feature vector for insider-threat analysis.
    """

    if not events:
        return {}

    user_id = events[0].user_id

    # -----------------------------
    # EVENT COUNTS
    # -----------------------------

    event_counts = Counter(
        event.event_type.value
        for event in events
    )

    # -----------------------------
    # ACTION COUNTS
    # -----------------------------

    action_counts = Counter(
        event.action
        for event in events
        if event.action is not None
    )

    # -----------------------------
    # NUMERIC VALUES
    # -----------------------------

    total_value = sum(
        event.value or 0
        for event in events
    )

    # Total amount of data transferred
    transfer_volume = sum(
        event.value or 0
        for event in events
        if event.event_type.value == "data_transfer"
    )

    # -----------------------------
    # TIME FEATURES
    # -----------------------------

    timestamps = [
        event.timestamp
        for event in events
    ]

    # Activity between 7 PM and 7 AM
    after_hours_count = sum(
        1
        for timestamp in timestamps
        if timestamp.hour < 7 or timestamp.hour >= 19
    )

    # Activity occurring on Saturday/Sunday
    weekend_count = sum(
        1
        for timestamp in timestamps
        if timestamp.weekday() >= 5
    )

    # -----------------------------
    # FEATURE VECTOR
    # -----------------------------

    features = {

        # User
        "user_id": user_id,

        # Overall activity
        "total_events": len(events),

        # Event counts
        "login_count": event_counts.get("login", 0),
        "logout_count": event_counts.get("logout", 0),
        "file_access_count": event_counts.get("file_access", 0),
        "file_copy_count": event_counts.get("file_copy", 0),
        "usb_connection_count": event_counts.get(
            "usb_connected", 0
        ),
        "web_activity_count": event_counts.get(
            "web_activity", 0
        ),
        "data_transfer_count": event_counts.get(
            "data_transfer", 0
        ),
        "email_activity_count": event_counts.get(
            "email_activity", 0
        ),

        # Action counts
        "read_count": action_counts.get("read", 0),
        "visit_count": action_counts.get("visit", 0),
        "bulk_copy_count": action_counts.get(
            "bulk_copy", 0
        ),
        "large_transfer_count": action_counts.get(
            "large_transfer", 0
        ),

        # Numeric features
        "total_value": total_value,
        "transfer_volume": transfer_volume,

        # Time-based features
        "after_hours_count": after_hours_count,
        "weekend_count": weekend_count,
    }

    return features