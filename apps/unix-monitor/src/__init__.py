"""unix-monitor source package (Phase 4 Slice C extraction).

Holds modules carved out of the legacy ``unix-monitor.py`` monolith. The
entry script adds its own directory to ``sys.path`` so these packages import
cleanly whether the tree is run in place or installed alongside the script.
"""
