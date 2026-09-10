"""secscan - a dependency-free static security scanner that explains its findings.

For each issue it reports:
  * what it would cost you if exploited (impact)
  * how easily it could be exploited, given how reachable it is here
  * how common the weakness is across the industry
  * what that vulnerability type has been doing in the news lately
"""

__version__ = "1.0.0"

from .knowledge import VULN_CLASSES, VulnClass  # noqa: F401
from .scanner import Finding, ScanReport, scan  # noqa: F401

__all__ = ["scan", "Finding", "ScanReport", "VulnClass", "VULN_CLASSES", "__version__"]
