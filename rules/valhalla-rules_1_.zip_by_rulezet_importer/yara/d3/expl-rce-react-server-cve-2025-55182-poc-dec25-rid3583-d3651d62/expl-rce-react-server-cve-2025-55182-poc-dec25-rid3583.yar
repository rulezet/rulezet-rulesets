rule EXPL_RCE_React_Server_CVE_2025_55182_POC_Dec25_RID3583 : CVE_2025_55182 DEMO EXPLOIT FILE {
   meta:
      description = "Detects RCE indicators related to the proof-of-concept code for the React Server Remote Code Execution Vulnerability (CVE-2025-55182)"
      author = "Florian Roth"
      reference = "https://www.youtube.com/watch?v=MmdwakT-Ve8"
      date = "2025-12-05 16:16:21"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CVE_2025_55182, DEMO, EXPLOIT, FILE"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "process.mainModule.require('child_process').execSync(" 
      $s2 = "$1:constructor:constructor" 
   condition: 
      all of them and not uint16 ( 0 ) == 0x3c3f
}