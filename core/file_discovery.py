"""
core/file_discovery.py
FiveM resource discovery engine.
Recursively scans a resources/ directory and identifies valid FiveM resources.
"""

import os
import re
import json
from dataclasses import dataclass, field
from typing import List, Optional, Dict


MANIFEST_NAMES = {"fxmanifest.lua", "__resource.lua"}

# Common FiveM framework identifiers
FRAMEWORK_PATTERNS: Dict[str, List[str]] = {
    "ESX": ["esx", "es_extended", "esx_core"],
    "QBCore": ["qb-core", "qbcore", "qb_core"],
    "Qbox": ["qbox", "ox_core"],
    "vRP": ["vrp", "vrpex"],
    "ox": ["ox_lib", "ox_inventory", "ox_target"],
    "standalone": ["standalone"],
}

# Extensions to consider as scannable code
LUA_EXTS = {".lua"}
JS_EXTS = {".js", ".mjs", ".ts"}
MANIFEST_FILES = {"fxmanifest.lua", "__resource.lua"}
ALL_CODE_EXTS = LUA_EXTS | JS_EXTS | {".html", ".htm", ".json"}

# File extensions to skip entirely (binary/media)
SKIP_EXTS = {
    ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico",
    ".mp3", ".mp4", ".ogg", ".wav", ".webm",
    ".dds", ".ytd", ".ydr", ".yft", ".ybn", ".ymap", ".ymf", ".ytyp",
    ".zip", ".rar", ".7z", ".tar", ".gz",
    ".exe", ".dll", ".pdb",
    ".ttf", ".otf", ".woff", ".woff2",
    ".pdf", ".doc", ".docx",
}


@dataclass
class FiveMFile:
    """Represents a single file within a FiveM resource."""
    absolute_path: str
    relative_path: str        # relative to resource root
    filename: str
    extension: str
    size_bytes: int
    file_type: str            # "lua", "js", "manifest", "html", "json", "other"
    is_manifest: bool = False
    is_client_script: bool = False
    is_server_script: bool = False
    is_shared_script: bool = False

    @property
    def is_code(self) -> bool:
        return self.extension in ALL_CODE_EXTS


@dataclass
class FiveMResource:
    """Represents a discovered FiveM resource directory."""
    name: str
    path: str                             # absolute path to resource root
    manifest_path: Optional[str] = None  # path to fxmanifest.lua or __resource.lua
    manifest_type: str = "none"          # "fxmanifest" | "__resource" | "none"
    framework: str = "unknown"
    files: List[FiveMFile] = field(default_factory=list)
    client_scripts: List[str] = field(default_factory=list)
    server_scripts: List[str] = field(default_factory=list)
    shared_scripts: List[str] = field(default_factory=list)
    exports: List[str] = field(default_factory=list)
    server_exports: List[str] = field(default_factory=list)
    dependencies: List[str] = field(default_factory=list)
    ui_page: Optional[str] = None
    has_nui: bool = False
    has_stream: bool = False

    @property
    def code_files(self) -> List[FiveMFile]:
        return [f for f in self.files if f.is_code]

    @property
    def lua_files(self) -> List[FiveMFile]:
        return [f for f in self.files if f.extension in LUA_EXTS]

    @property
    def js_files(self) -> List[FiveMFile]:
        return [f for f in self.files if f.extension in JS_EXTS]

    @property
    def manifest_file(self) -> Optional[FiveMFile]:
        for f in self.files:
            if f.is_manifest:
                return f
        return None


def _classify_file_type(ext: str, filename: str) -> str:
    if filename in MANIFEST_FILES:
        return "manifest"
    if ext in LUA_EXTS:
        return "lua"
    if ext in JS_EXTS:
        return "js"
    if ext in {".html", ".htm"}:
        return "html"
    if ext == ".json":
        return "json"
    return "other"


def _detect_framework(resource_name: str, resource_path: str) -> str:
    """Detect which FiveM framework a resource belongs to."""
    name_lower = resource_name.lower()
    path_lower = resource_path.lower().replace("\\", "/")

    for framework, patterns in FRAMEWORK_PATTERNS.items():
        for pat in patterns:
            if pat.lower() in name_lower or pat.lower() in path_lower:
                return framework

    # Check parent directory names (e.g., [esx], [qb])
    parts = path_lower.split("/")
    for part in parts:
        part_clean = part.strip("[]")
        for framework, patterns in FRAMEWORK_PATTERNS.items():
            for pat in patterns:
                if pat.lower() in part_clean:
                    return framework

    return "standalone"


def _extract_manifest_info(manifest_path: str, resource: FiveMResource) -> None:
    """
    Parse fxmanifest.lua or __resource.lua to extract script lists,
    dependencies, exports, and ui_page.
    Does NOT execute any Lua — pure regex/text parsing.
    """
    try:
        with open(manifest_path, "r", encoding="utf-8", errors="replace") as f:
            content = f.read()
    except Exception:
        return

    def extract_list_block(keyword: str, text: str) -> List[str]:
        """Extract items from a block like: keyword { 'item1', 'item2' }"""
        results = []
        # Multi-value block form
        pattern = rf"{re.escape(keyword)}\s*\{{([^}}]*)\}}"
        for m in re.finditer(pattern, text, re.DOTALL | re.IGNORECASE):
            block = m.group(1)
            items = re.findall(r"['\"]([^'\"]+)['\"]", block)
            results.extend(items)
        # Single-value form
        pattern2 = rf"{re.escape(keyword)}\s+['\"]([^'\"]+)['\"]"
        for m in re.finditer(pattern2, text, re.IGNORECASE):
            results.append(m.group(1))
        return results

    resource.client_scripts = extract_list_block("client_script", content) + \
                               extract_list_block("client_scripts", content)
    resource.server_scripts = extract_list_block("server_script", content) + \
                               extract_list_block("server_scripts", content)
    resource.shared_scripts = extract_list_block("shared_script", content) + \
                               extract_list_block("shared_scripts", content)
    resource.dependencies = extract_list_block("dependency", content) + \
                             extract_list_block("dependencies", content)
    resource.exports = extract_list_block("export", content) + \
                       extract_list_block("exports", content)
    resource.server_exports = extract_list_block("server_export", content) + \
                               extract_list_block("server_exports", content)

    # ui_page
    ui_match = re.search(r"ui_page\s+['\"]([^'\"]+)['\"]", content, re.IGNORECASE)
    if ui_match:
        resource.ui_page = ui_match.group(1)


def _scan_resource_directory(resource_path: str, resource_name: str,
                              max_file_size_mb: int = 50) -> FiveMResource:
    """Walk a resource directory and build a FiveMResource object."""
    resource = FiveMResource(
        name=resource_name,
        path=resource_path,
        framework=_detect_framework(resource_name, resource_path),
    )

    max_bytes = max_file_size_mb * 1024 * 1024

    for root, dirs, filenames in os.walk(resource_path):
        from core import database as db
        scan_hidden = db.get_setting("scan_hidden", False)
        
        # Skip hidden directories if scan_hidden is disabled
        if not scan_hidden:
            dirs[:] = [d for d in dirs if not d.startswith(".")]

        rel_root = os.path.relpath(root, resource_path)

        for filename in filenames:
            # Skip hidden files if scan_hidden is disabled
            if not scan_hidden and filename.startswith("."):
                continue
                
            abs_path = os.path.join(root, filename)
            rel_path = os.path.normpath(os.path.join(rel_root, filename))
            if rel_path.startswith("."):
                rel_path = rel_path[2:]  # remove leading ./

            ext = os.path.splitext(filename)[1].lower()

            # Skip binary/media files
            if ext in SKIP_EXTS:
                continue

            try:
                size = os.path.getsize(abs_path)
            except OSError:
                size = 0

            if size > max_bytes:
                continue  # Skip very large files

            file_type = _classify_file_type(ext, filename.lower())
            is_manifest = filename.lower() in MANIFEST_FILES

            fivem_file = FiveMFile(
                absolute_path=abs_path,
                relative_path=rel_path,
                filename=filename,
                extension=ext,
                size_bytes=size,
                file_type=file_type,
                is_manifest=is_manifest,
            )

            resource.files.append(fivem_file)

            if is_manifest and resource.manifest_path is None:
                resource.manifest_path = abs_path
                if filename.lower() == "fxmanifest.lua":
                    resource.manifest_type = "fxmanifest"
                else:
                    resource.manifest_type = "__resource"

        # Detect NUI/stream folders
        if "html" in dirs or "web" in dirs or "nui" in dirs:
            resource.has_nui = True
        if "stream" in dirs:
            resource.has_stream = True

    if resource.manifest_path:
        _extract_manifest_info(resource.manifest_path, resource)

        # Mark files according to manifest declarations
        declared = set()
        for script_list in [resource.client_scripts, resource.server_scripts,
                             resource.shared_scripts]:
            for script in script_list:
                declared.add(script.replace("/", os.sep).replace("\\", os.sep))

        for fivem_file in resource.files:
            if fivem_file.relative_path in resource.client_scripts or \
               fivem_file.filename in resource.client_scripts:
                fivem_file.is_client_script = True
            if fivem_file.relative_path in resource.server_scripts or \
               fivem_file.filename in resource.server_scripts:
                fivem_file.is_server_script = True
            if fivem_file.relative_path in resource.shared_scripts or \
               fivem_file.filename in resource.shared_scripts:
                fivem_file.is_shared_script = True

    return resource


def is_fivem_resource(directory: str) -> bool:
    """Check if a directory is a valid FiveM resource (has a manifest)."""
    for mf in MANIFEST_NAMES:
        if os.path.exists(os.path.join(directory, mf)):
            return True
    return False


def discover_resources(resources_path: str, max_depth: int = 5) -> List[FiveMResource]:
    """
    Recursively discover all FiveM resources under a given path.
    Supports nested category folders like [esx], [qb], [standalone], etc.
    """
    discovered: List[FiveMResource] = []

    if not os.path.isdir(resources_path):
        return discovered

    def _walk(current_path: str, depth: int) -> None:
        if depth <= 0:
            return

        try:
            entries = os.listdir(current_path)
        except PermissionError:
            return

        for entry in entries:
            entry_path = os.path.join(current_path, entry)
            if not os.path.isdir(entry_path):
                continue
            if entry.startswith("."):
                continue

            if is_fivem_resource(entry_path):
                resource = _scan_resource_directory(entry_path, entry)
                discovered.append(resource)
            else:
                # Could be a category folder like [esx], [standalone]
                _walk(entry_path, depth - 1)

    _walk(resources_path, max_depth)
    return discovered


def discover_single_resource(resource_path: str) -> Optional[FiveMResource]:
    """Discover and scan a single resource directory."""
    if not os.path.isdir(resource_path):
        return None
    name = os.path.basename(resource_path.rstrip(os.sep))
    return _scan_resource_directory(resource_path, name)


def get_quick_scan_files(resource: FiveMResource, quick_names: List[str]) -> List[FiveMFile]:
    """Return only the priority files for a quick scan."""
    quick_set = {n.lower() for n in quick_names}
    result = []
    for f in resource.files:
        if f.filename.lower() in quick_set or f.is_manifest:
            result.append(f)
    return result if result else resource.code_files
