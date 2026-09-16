rule CN_Honker_IIS6_iis6_RID2DBC : CHINA DEMO EXE FILE HKTL {
   meta:
      description = "Sample from CN Honker Pentest Toolset - file iis6.com"
      author = "Florian Roth"
      reference = "Disclosed CN Honker Pentest Toolset"
      date = "2015-06-23 10:44:31"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, EXE, FILE, HKTL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "GetMod;ul" fullword ascii
      $s1 = "excjpb" fullword ascii
      $s2 = "LEAUT1" fullword ascii
      $s3 = "EnumProcessModules" fullword ascii
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 50KB and all of them
}