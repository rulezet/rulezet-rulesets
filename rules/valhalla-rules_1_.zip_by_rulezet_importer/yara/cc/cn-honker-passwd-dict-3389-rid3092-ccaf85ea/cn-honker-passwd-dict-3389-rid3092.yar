rule CN_Honker_passwd_dict_3389_RID3092 : CHINA DEMO SCRIPT SUSP {
   meta:
      description = "Script from disclosed CN Honker Pentest Toolset - file 3389.txt"
      author = "Florian Roth"
      reference = "Disclosed CN Honker Pentest Toolset"
      date = "2015-06-23 12:45:31"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, SCRIPT, SUSP"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "654321" fullword ascii
      $s1 = "admin123" fullword ascii
      $s2 = "admin123456" fullword ascii
      $s3 = "administrator" fullword ascii
      $s4 = "passwd" fullword ascii
      $s5 = "password" fullword ascii
      $s7 = "12345678" fullword ascii
   condition: 
      filesize < 1KB and all of them
}