"""Stage 5 -- Respuesta al usuario.

Public API:

    respond(decision, item, state=None) -> str   Persist + return the user-facing message.
    format_message(decision, item) -> str        Just the formatting, no side effects.
"""

from .response import format_message, respond

__all__ = ["respond", "format_message"]
