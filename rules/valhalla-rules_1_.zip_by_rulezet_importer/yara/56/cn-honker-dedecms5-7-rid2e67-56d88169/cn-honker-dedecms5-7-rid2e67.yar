rule CN_Honker_dedecms5_7_RID2E67 : CHINA DEMO EXE FILE HKTL {
   meta:
      description = "Sample from CN Honker Pentest Toolset - file dedecms5.7.exe"
      author = "Florian Roth"
      reference = "Disclosed CN Honker Pentest Toolset"
      date = "2015-06-23 11:13:01"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, EXE, FILE, HKTL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "/data/admin/ver.txt" fullword ascii
      $s2 = "SkinH_EL.dll" fullword ascii
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 830KB and all of them
}