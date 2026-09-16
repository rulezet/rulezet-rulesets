rule CN_Honker_exp_ms11080_RID2E4D : CHINA DEMO EXE FILE HKTL {
   meta:
      description = "Sample from CN Honker Pentest Toolset - file ms11080.exe"
      author = "Florian Roth"
      reference = "Disclosed CN Honker Pentest Toolset"
      date = "2015-06-23 11:08:41"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, EXE, FILE, HKTL"
      minimum_yara = "3.5.0"
      
   strings:
      $s2 = "[*] command add user 90sec 90sec" fullword ascii
      $s6 = "[*] Add to Administrators success" fullword ascii
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 840KB and all of them
}