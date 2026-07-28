"""Steam Workshop Analyzer — malware detection pipeline for Wallpaper Engine.

Package layout (one subpackage per etapa of the design doc):

    etapa0_ingesta    Download from Steam Workshop into quarantine
    etapa1_triage     Format triage (drop safe image/video formats)
    etapa2_static     Static analysis of scripts / PE binaries
    etapa3_sandbox    Dynamic sandbox (integration spec)
    etapa4_decision   Decision engine  <-- implemented
    etapa5_response   User response / reporting

Shared data contracts live in `swa.models`.
"""

__version__ = "0.1.0"
