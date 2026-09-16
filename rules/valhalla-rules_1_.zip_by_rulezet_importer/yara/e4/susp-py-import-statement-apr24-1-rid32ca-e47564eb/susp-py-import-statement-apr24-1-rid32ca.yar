rule SUSP_PY_Import_Statement_Apr24_1_RID32CA : DEMO SCRIPT SUSP T1059_006 {
   meta:
      description = "Detects suspicious Python import statement and socket usage often found in Python reverse shells"
      author = "Florian Roth"
      reference = "https://www.volexity.com/blog/2024/04/12/zero-day-exploitation-of-unauthenticated-remote-code-execution-vulnerability-in-globalprotect-cve-2024-3400/"
      date = "2024-04-15 14:20:11"
      score = 65
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, SUSP, T1059_006"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = "import sys,socket,os,pty;s=socket.socket(" 
   condition: 
      1 of them
}