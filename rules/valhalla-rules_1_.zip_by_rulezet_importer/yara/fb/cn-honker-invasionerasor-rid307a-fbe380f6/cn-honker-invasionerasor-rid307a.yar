rule CN_Honker_InvasionErasor_RID307A : CHINA DEMO EXE FILE HKTL {
   meta:
      description = "Sample from CN Honker Pentest Toolset - file InvasionErasor.exe"
      author = "Florian Roth"
      reference = "Disclosed CN Honker Pentest Toolset"
      date = "2015-06-23 12:41:31"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, EXE, FILE, HKTL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "c:\\windows\\system32\\config\\*.*" fullword wide
      $s2 = "c:\\winnt\\*.txt" fullword wide
      $s3 = "Command1" fullword ascii
      $s4 = "Win2003" fullword ascii
      $s5 = "Win 2000" fullword ascii
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 60KB and all of them
}