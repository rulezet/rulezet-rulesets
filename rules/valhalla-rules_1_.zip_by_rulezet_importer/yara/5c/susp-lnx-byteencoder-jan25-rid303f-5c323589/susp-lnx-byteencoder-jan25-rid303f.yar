rule SUSP_LNX_ByteEncoder_Jan25_RID303F : DEMO FILE LINUX SUSP {
   meta:
      description = "Detects Linux binaries that encode bytes by splitting them into upper and lower nibbles and mapping them to custom lookup tables, seen being used by SEASPY and Bluez backdoors"
      author = "MalGamy (Nextron Systems)"
      reference = "https://www.securityweek.com/newly-discovered-turla-malware-targets-linux-systems/"
      date = "2025-01-23 12:31:41"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, FILE, LINUX, SUSP"
      minimum_yara = "3.5.0"
      
   strings:
      $op1 = { 8B 45 FC 48 63 D0 48 8B 45 A8 48 01 C2 8B 45 BC C1 F8 04 83 E0 0F 48 98 0F B6 44 05 E0 88 02 } 
      $op2 = { 8B 45 FC 48 98 48 8D 50 01 48 8B 45 A8 48 01 C2 8B 45 BC 83 E0 0F 48 98 0F B6 44 05 C0 88 02 } 
   condition: 
      uint32be ( 0 ) == 0x7f454c46 and filesize < 4MB and all of them
}