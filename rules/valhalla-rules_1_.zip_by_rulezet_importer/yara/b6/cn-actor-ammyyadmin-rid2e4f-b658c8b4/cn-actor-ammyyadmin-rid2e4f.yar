rule CN_Actor_AmmyyAdmin_RID2E4F : CHINA DEMO EXE FILE MAL T1219 {
   meta:
      description = "Detects Ammyy Admin Downloader"
      author = "Florian Roth"
      reference = "Internal Research - CN Actor"
      date = "2017-06-22 11:09:01"
      score = 60
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "1831806fc27d496f0f9dcfd8402724189deaeb5f8bcf0118f3d6484d0bdee9ed"
      tags = "CHINA, DEMO, EXE, FILE, MAL, T1219"
      minimum_yara = "3.5.0"
      
   strings:
      $x2 = "\\Ammyy\\sources\\main\\Downloader.cpp" ascii
   condition: 
      ( uint16 ( 0 ) == 0x5a4d and filesize < 2000KB and all of them )
}