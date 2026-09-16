rule CN_Actor_RA_Tool_Ammyy_mscorsvw_RID3338 : CHINA DEMO EXE FILE MAL T1219 {
   meta:
      description = "Detects Ammyy remote access tool"
      author = "Florian Roth"
      reference = "Internal Research - CN Actor"
      date = "2017-06-22 14:38:31"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "1831806fc27d496f0f9dcfd8402724189deaeb5f8bcf0118f3d6484d0bdee9ed"
      hash2 = "d9ec0a1be7cd218042c54bfbc12000662b85349a6b78731a09ed336e5d3cf0b4"
      tags = "CHINA, DEMO, EXE, FILE, MAL, T1219"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "Please enter password for accessing remote computer" fullword ascii
      $s2 = "Die Zugriffsanforderung wurde vom Remotecomputer abgelehnt" fullword ascii
      $s3 = "It will automatically be run the next time this computer is restart or you can start it manually" fullword ascii
   condition: 
      ( uint16 ( 0 ) == 0x5a4d and filesize < 4000KB and 3 of them )
}