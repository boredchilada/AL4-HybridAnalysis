"""
Hybrid Analysis Service for Assemblyline v4

This service integrates with the Hybrid Analysis API to perform automated malware analysis.
It provides detailed analysis results including behavioral analysis, process activity,
network activity, file activity, and registry modifications.
"""

from .core.service import HybridAnalysisService

__all__ = ['HybridAnalysisService']