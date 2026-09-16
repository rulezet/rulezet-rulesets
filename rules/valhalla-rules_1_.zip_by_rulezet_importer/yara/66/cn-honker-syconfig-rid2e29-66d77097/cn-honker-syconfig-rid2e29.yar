rule CN_Honker_syconfig_RID2E29 : CHINA DEMO FILE SCRIPT SUSP {
   meta:
      description = "Script from disclosed CN Honker Pentest Toolset - file syconfig.dll"
      author = "Florian Roth"
      reference = "Disclosed CN Honker Pentest Toolset"
      date = "2015-06-23 11:02:41"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, FILE, SCRIPT, SUSP"
      minimum_yara = "3.5.0"
      
   strings:
      $s9 = "Hashq.CrackHost+FormUnit" fullword ascii
   condition: 
      uint16 ( 0 ) == 0x0100 and filesize < 18KB and all of them
}