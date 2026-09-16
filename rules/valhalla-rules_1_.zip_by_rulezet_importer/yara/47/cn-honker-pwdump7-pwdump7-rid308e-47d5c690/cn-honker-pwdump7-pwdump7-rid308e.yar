rule CN_Honker_Pwdump7_Pwdump7_RID308E : CHINA DEMO SCRIPT SUSP {
   meta:
      description = "Script from disclosed CN Honker Pentest Toolset - file Pwdump7.bat"
      author = "Florian Roth"
      reference = "Disclosed CN Honker Pentest Toolset"
      date = "2015-06-23 12:44:51"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, SCRIPT, SUSP"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "Pwdump7.exe >pass.txt" fullword ascii
   condition: 
      filesize < 1KB and all of them
}