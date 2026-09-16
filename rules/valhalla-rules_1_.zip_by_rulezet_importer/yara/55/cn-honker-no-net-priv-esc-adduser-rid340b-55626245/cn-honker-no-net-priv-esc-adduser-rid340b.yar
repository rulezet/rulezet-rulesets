rule CN_Honker_no_net_priv_esc_AddUser_RID340B : CHINA DEMO EXE FILE HKTL T1136 {
   meta:
      description = "Sample from CN Honker Pentest Toolset - file AddUser.dll"
      author = "Florian Roth"
      reference = "Disclosed CN Honker Pentest Toolset"
      date = "2015-06-23 15:13:41"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, EXE, FILE, HKTL, T1136"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "PECompact2" fullword ascii
      $s1 = "adduser" fullword ascii
      $s5 = "OagaBoxA" fullword ascii
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 115KB and all of them
}