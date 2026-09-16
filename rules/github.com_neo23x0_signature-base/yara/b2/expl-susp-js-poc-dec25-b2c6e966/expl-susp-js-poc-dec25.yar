rule EXPL_SUSP_JS_POC_Dec25 {
   meta:
      description = "Detects RCE indicators related to the proof-of-concept code for the React Server Remote Code Execution Vulnerability (CVE-2025-55182) but could be used in other JavaScript based PoC code as well"
      author = "Florian Roth"
      reference = "https://github.com/msanft/CVE-2025-55182/blob/main/poc.py"
      date = "2025-12-05"
      modified = "2025-12-06"
      score = 70
   strings:
      $xr1 = /process\.mainModule\.require\(["']child_process["']\).{5,40}\(["'](whoami|powershell|\/bin\/sh|\/bin\/bash|wget|curl|cat \/etc\/passwd|uname|id["'])/
   condition:
      1 of them
            and not uint16(0) == 0x3c3f
}