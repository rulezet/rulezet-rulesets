rule CN_Honker_LPK2_0_LPK_RID2DB5 : CHINA DEMO EXE FILE HKTL {
   meta:
      description = "Sample from CN Honker Pentest Toolset - file LPK.DAT"
      author = "Florian Roth"
      reference = "Disclosed CN Honker Pentest Toolset"
      date = "2015-06-23 10:43:21"
      score = 90
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, EXE, FILE, HKTL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "\\sethc.exe /G everyone:F" ascii
      $s2 = "net1 user guest guest123!@#" fullword ascii
      $s3 = "\\dllcache\\sethc.exe" ascii
      $s4 = "sathc.exe 211" fullword ascii
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 1030KB and all of them
}