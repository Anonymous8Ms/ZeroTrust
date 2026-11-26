"""Safe, fixed reason codes shared by the adapters."""


class Reject(Exception):
    """Carry only adapter-defined reason codes across the file boundary."""
