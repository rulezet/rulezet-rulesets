rule CN_Honker_ASP_wshell_RID2E99 : CHINA DEMO FILE HKTL {
   meta:
      description = "Sample from CN Honker Pentest Toolset - file wshell.txt"
      author = "Florian Roth"
      reference = "Disclosed CN Honker Pentest Toolset"
      date = "2015-06-23 11:21:21"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, FILE, HKTL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "<%@ LANGUAGE = VBScript.Encode %><%" fullword ascii
      $s1 = "UserPass=" 
      $s2 = "VerName=" 
      $s3 = "StateName=" 
   condition: 
      uint16 ( 0 ) == 0x253c and filesize < 200KB and all of them
}