rule CN_Honker_T00ls_Lpk_Sethc_v2_RID313D : CHINA DEMO EXE FILE HKTL T1546_008 {
   meta:
      description = "Sample from CN Honker Pentest Toolset - file T00ls Lpk Sethc v2.exe"
      author = "Florian Roth"
      reference = "Disclosed CN Honker Pentest Toolset"
      date = "2015-06-23 13:14:01"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, EXE, FILE, HKTL, T1546_008"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "LOADER ERROR" fullword ascii
      $s2 = "The procedure entry point %s could not be located in the dynamic link library %s" fullword ascii
      $s3 = "2011-2012 T00LS&RICES" fullword wide
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 800KB and all of them
}