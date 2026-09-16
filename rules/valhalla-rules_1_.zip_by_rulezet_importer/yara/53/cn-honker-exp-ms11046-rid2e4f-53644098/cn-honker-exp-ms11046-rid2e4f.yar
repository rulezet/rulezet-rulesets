rule CN_Honker_exp_ms11046_RID2E4F : CHINA DEMO EXE FILE HKTL {
   meta:
      description = "Sample from CN Honker Pentest Toolset - file ms11046.exe"
      author = "Florian Roth"
      reference = "Disclosed CN Honker Pentest Toolset"
      date = "2015-06-23 11:09:01"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, EXE, FILE, HKTL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "[*] Token system command" fullword ascii
      $s1 = "[*] command add user 90sec 90sec" fullword ascii
      $s2 = "[*] Add to Administrators success" fullword ascii
      $s3 = "Program: %s%s%s%s%s%s%s%s%s%s%s" fullword ascii
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 300KB and all of them
}