rule CN_Honker_T00ls_Lpk_Sethc_v3_LPK_RID3284 : CHINA DEMO EXE FILE HKTL T1546_008 {
   meta:
      description = "Sample from CN Honker Pentest Toolset - file LPK.DAT"
      author = "Florian Roth"
      reference = "Disclosed CN Honker Pentest Toolset"
      date = "2015-06-23 14:08:31"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, EXE, FILE, HKTL, T1546_008"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "FreeHostKillexe.exe" fullword ascii
      $s2 = "\\sethc.exe /G everyone:F" ascii
      $s3 = "c:\\1.exe" fullword ascii
      $s4 = "Set user Group Error! Username:" fullword ascii
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 400KB and all of them
}