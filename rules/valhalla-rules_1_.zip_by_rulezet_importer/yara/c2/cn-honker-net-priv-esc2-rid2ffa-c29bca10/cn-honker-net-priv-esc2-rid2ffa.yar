rule CN_Honker_net_priv_esc2_RID2FFA : CHINA DEMO EXE FILE HKTL {
   meta:
      description = "Sample from CN Honker Pentest Toolset - file net-priv-esc2.exe"
      author = "Florian Roth"
      reference = "Disclosed CN Honker Pentest Toolset"
      date = "2015-06-23 12:20:11"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, EXE, FILE, HKTL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "Usage:%s username password" fullword ascii
      $s2 = "<www.darkst.com>" fullword ascii
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 17KB and all of them
}