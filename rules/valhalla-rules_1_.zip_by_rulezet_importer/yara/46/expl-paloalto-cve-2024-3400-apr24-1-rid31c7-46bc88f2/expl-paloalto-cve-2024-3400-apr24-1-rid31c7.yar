rule EXPL_PaloAlto_CVE_2024_3400_Apr24_1_RID31C7 : CVE_2024_3400 DEMO EXPLOIT {
   meta:
      description = "Detects characteristics of the exploit code used in attacks against Palo Alto GlobalProtect CVE-2024-3400"
      author = "Florian Roth"
      reference = "https://www.volexity.com/blog/2024/04/12/zero-day-exploitation-of-unauthenticated-remote-code-execution-vulnerability-in-globalprotect-cve-2024-3400/"
      date = "2024-04-15 13:37:01"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CVE_2024_3400, DEMO, EXPLOIT"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = "SESSID=../../../../opt/panlogs/" 
      $x2 = "SESSID=./../../../../opt/panlogs/" 
      $sa1 = "SESSID=../../../../" 
      $sa2 = "SESSID=./../../../../" 
      $sb2 = "${IFS}" 
   condition: 
      1 of ( $x* ) or ( 1 of ( $sa* ) and $sb2 )
}