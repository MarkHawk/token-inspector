"""Time formatting: every timestamp is shown in UTC and relative to now."""

import datetime as dt


def utc(t):
    return t.astimezone(dt.UTC).strftime("%Y-%m-%d %H:%M:%S UTC")


def duration(seconds):
    """A short human duration: 45 s, 3 min, 2 h 5 min, 12 days."""
    s = int(abs(seconds))
    if s < 90:
        return f"{s} s"
    if s < 90 * 60:
        return f"{round(s / 60)} min"
    if s < 48 * 3600:
        h, m = divmod(round(s / 60), 60)
        return f"{h} h {m} min" if m else f"{h} h"
    return f"{round(s / 86400)} days"


def relative(t, now):
    """'in 4 min', '3 h ago' or 'now'."""
    delta = (t - now).total_seconds()
    if abs(delta) < 1:
        return "now"
    return f"in {duration(delta)}" if delta > 0 else f"{duration(delta)} ago"


def utc_relative(t, now):
    return f"{utc(t)} ({relative(t, now)})"


def near_whole_hours(seconds, tolerance=120):
    """True if a gap is a whole number of hours, which suggests a timezone bug."""
    s = abs(seconds)
    hours = round(s / 3600)
    return hours >= 1 and abs(s - hours * 3600) <= tolerance
