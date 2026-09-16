rule EXPL_RCE_React_Server_Next_JS_CVE_2025_66478_Errors_Dec25_RID3A22 : CVE_2025_55182 CVE_2025_66478 DEMO EXPLOIT T1059_007 {
   meta:
      description = "Detects error messages caused by the exploitation of the React Server Remote Code Execution Vulnerability (CVE-2025-55182) in Next.js applications (CVE-2025-66478). This can also be caused by vulnerability scanning."
      author = "Florian Roth"
      reference = "https://github.com/Malayke/Next.js-RSC-RCE-Scanner-CVE-2025-66478"
      date = "2025-12-05 19:33:31"
      score = 65
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CVE_2025_55182, CVE_2025_66478, DEMO, EXPLOIT, T1059_007"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "[Error: NEXT_REDIRECT]" 
      $s2 = "digest: 'uid=0(root) gid=0(root)" 
   condition: 
      all of them
}