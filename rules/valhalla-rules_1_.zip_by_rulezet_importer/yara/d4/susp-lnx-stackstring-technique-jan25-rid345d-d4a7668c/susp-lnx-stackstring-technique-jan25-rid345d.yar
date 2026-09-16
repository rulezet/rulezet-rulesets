rule SUSP_LNX_StackString_Technique_Jan25_RID345D : DEMO FILE LINUX SUSP {
   meta:
      description = "Detects Linux binaries using stack-based string manipulation techniques, which are often used to generate PTY (pseudo-terminal) device names for stealth or persistence, seen being used by SEASPY and Bluez backdoors"
      author = "MalGamy (Nextron Systems)"
      reference = "https://www.securityweek.com/newly-discovered-turla-malware-targets-linux-systems/"
      date = "2025-01-23 15:27:21"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, FILE, LINUX, SUSP"
      minimum_yara = "3.5.0"
      
   strings:
      $op1 = { C7 45 E0 70 71 72 73 C7 45 E4 74 75 76 77 C7 45 E8 78 79 7A 61 C7 45 EC 62 63 64 65 C6 45 F0 00 C7 45 C0 30 31 32 33 C7 45 C4 34 35 36 37 C7 45 C8 38 39 61 62 C7 45 CC 63 64 65 66 } 
   condition: 
      uint32be ( 0 ) == 0x7f454c46 and filesize < 4MB and $op1
}