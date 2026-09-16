rule CN_Honker_T00ls_Lpk_Sethc_v4_0_RID31CE : CHINA DEMO EXE FILE HKTL T1546_008 {
   meta:
      description = "Sample from CN Honker Pentest Toolset - file T00ls Lpk Sethc v4.0.exe"
      author = "Florian Roth"
      reference = "Disclosed CN Honker Pentest Toolset"
      date = "2015-06-23 13:38:11"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, EXE, FILE, HKTL, T1546_008"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "LOADER ERROR" fullword ascii
      $s15 = "2011-2012 T00LS&RICES" fullword wide
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 2077KB and all of them
}