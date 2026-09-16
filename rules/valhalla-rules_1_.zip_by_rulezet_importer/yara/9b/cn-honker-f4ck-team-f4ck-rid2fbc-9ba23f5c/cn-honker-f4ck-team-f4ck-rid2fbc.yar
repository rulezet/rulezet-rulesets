rule CN_Honker_F4ck_Team_f4ck_RID2FBC : CHINA DEMO SCRIPT SUSP {
   meta:
      description = "Script from disclosed CN Honker Pentest Toolset - file f4ck.txt"
      author = "Florian Roth"
      reference = "Disclosed CN Honker Pentest Toolset"
      date = "2015-06-23 12:09:51"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, SCRIPT, SUSP"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "PassWord:F4ckTeam!@#" fullword ascii
      $s1 = "UserName:F4ck" fullword ascii
      $s2 = "F4ck Team" fullword ascii
   condition: 
      filesize < 1KB and all of them
}