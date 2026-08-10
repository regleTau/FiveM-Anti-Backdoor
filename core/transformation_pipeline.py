"""
core/transformation_pipeline.py
Coordinates file classification, deobfuscation passes, decryption,
and runs threat analysis on recovered contents.
"""

import os
from typing import Dict, Any, List, Optional
from core.file_classifier import classify_file
from core.deobfuscator import StaticDeobfuscator
from core.decryptor import DecryptionManager
from core.source_mapper import SourceMapper
from core.risk_scorer import DetectionResult, sort_detections_by_severity


class TransformationPipeline:
    """Manages classification, recovery, and threat scan steps for obfuscated/encrypted resources."""

    def __init__(self) -> None:
        self.deobfuscator = StaticDeobfuscator()
        self.decryptor = DecryptionManager()

    def process_file(self, file_path: str, decryption_key: Optional[str] = None) -> Dict[str, Any]:
        """
        Runs the full classification and deobfuscation/decryption pipeline.
        Returns pipeline results, logs, and recovered threat detections.
        """
        # 1. Classification
        cls_info = classify_file(file_path)
        classification = cls_info.get("classification", "TEXT")
        
        # Read file contents
        content_str = ""
        try:
            with open(file_path, "r", encoding="utf-8", errors="replace") as f:
                content_str = f.read()
        except Exception as e:
            return {"error": f"Failed to read file: {e}"}

        recovered_content = content_str
        logs = []
        decryption_status = "Not Encrypted"

        # 2. Handle Decryption if required
        if classification == "ENCRYPTED":
            if not decryption_key:
                decryption_status = "Requires key"
                return {
                    "classification": classification,
                    "entropy": cls_info.get("entropy"),
                    "decryption_status": decryption_status,
                    "recovered_content": "",
                    "logs": ["Encrypted content detected. A valid decryption key is required."],
                    "detections": [],
                }
            
            res = self.decryptor.decrypt(file_path, decryption_key)
            if res.get("success"):
                recovered_content = res.get("decrypted_content", "")
                decryption_status = "Decrypted"
                logs.append(f"Decryption successful using algorithm: {res.get('algorithm')}")
            else:
                decryption_status = "Failed"
                logs.append("Decryption failed. Invalid key.")
                return {
                    "classification": classification,
                    "entropy": cls_info.get("entropy"),
                    "decryption_status": decryption_status,
                    "recovered_content": "",
                    "logs": logs,
                    "detections": [],
                }

        # 3. Handle Deobfuscation passes
        deobfuscation_status = "Not Obfuscated"
        if classification == "OBFUSCATED" or classification == "ENCODED":
            recovered_content, deob_logs = self.deobfuscator.deobfuscate(recovered_content)
            logs.extend(deob_logs)
            deobfuscation_status = "Success" if len(deob_logs) > 0 and deob_logs[0] != "No obfuscation layers identified." else "No layers removed"

        # 4. Threat Scan on Recovered Code
        detections: List[DetectionResult] = []
        if recovered_content != content_str:
            # We recovered new source content! Run Lua/JS static analyzers on recovered text
            ext = os.path.splitext(file_path)[1].lower()
            
            # Temporary file write inside temp directory to feed into existing analyzers
            # (or we can pass string directly if analyzers support it, but since they read file paths,
            # we write it to a temporary analysis scratch pad)
            temp_scratch = os.path.join(os.path.dirname(file_path), f".recovered_{os.path.basename(file_path)}")
            try:
                with open(temp_scratch, "w", encoding="utf-8") as f:
                    f.write(recovered_content)
                
                # Run standard analyzers
                if ext == ".lua":
                    from analyzers.lua_analyzer import analyze_lua_file
                    raw_detections = analyze_lua_file(temp_scratch, resource_name="recovered_payload")
                else:
                    from analyzers.js_analyzer import analyze_js_file
                    raw_detections = analyze_js_file(temp_scratch, resource_name="recovered_payload")

                # Restore original file path references in detections and perform source mapping
                mapper = SourceMapper(content_str, recovered_content)
                for det in raw_detections:
                    # Map line number
                    mapping = mapper.map_line(det.line_number)
                    orig_line = mapping.get("original_line_number", -1)
                    
                    # Create updated detection
                    det.file_path = file_path
                    if mapping.get("reliable") and orig_line != -1:
                        det.line_number = orig_line
                        det.description += f" (Mapped from recovered payload line {orig_line})"
                    else:
                        det.line_number = -1
                        det.description += f" (Threat in recovered payload; exact source mapping unreliable)"
                    
                    detections.append(det)

            except Exception as e:
                logs.append(f"Failed to analyze recovered content: {e}")
            finally:
                if os.path.exists(temp_scratch):
                    try:
                        os.remove(temp_scratch)
                    except Exception:
                        pass

        return {
            "classification": classification,
            "confidence": cls_info.get("confidence", 80.0),
            "entropy": cls_info.get("entropy", 0.0),
            "decryption_status": decryption_status,
            "deobfuscation_status": deobfuscation_status,
            "recovered_content": recovered_content,
            "logs": logs,
            "detections": detections,
        }
