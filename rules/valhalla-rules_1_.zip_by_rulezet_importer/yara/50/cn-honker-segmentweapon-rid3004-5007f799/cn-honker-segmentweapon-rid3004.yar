rule CN_Honker_SegmentWeapon_RID3004 : CHINA DEMO EXE FILE HKTL {
   meta:
      description = "Sample from CN Honker Pentest Toolset - file SegmentWeapon.exe"
      author = "Florian Roth"
      reference = "Disclosed CN Honker Pentest Toolset"
      date = "2015-06-23 12:21:51"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, EXE, FILE, HKTL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "C:\\WINDOWS\\system32\\msvbvm60.dll\\3" fullword ascii
      $s1 = "http://www.nforange.com/inc/1.asp?" fullword wide
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 100KB and all of them
}