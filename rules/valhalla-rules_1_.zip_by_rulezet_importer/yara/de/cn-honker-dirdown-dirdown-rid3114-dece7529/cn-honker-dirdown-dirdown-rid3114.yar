rule CN_Honker_dirdown_dirdown_RID3114 : CHINA DEMO EXE FILE HKTL {
   meta:
      description = "Sample from CN Honker Pentest Toolset - file dirdown.exe"
      author = "Florian Roth"
      reference = "Disclosed CN Honker Pentest Toolset"
      date = "2015-06-23 13:07:11"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      modified = "2022-12-21"
      tags = "CHINA, DEMO, EXE, FILE, HKTL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "\\Decompress\\obj\\Release\\Decompress.pdb" ascii
      $s1 = "Decompress.exe" fullword wide
      $s5 = "Get8Bytes" fullword ascii
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 45KB and all of them
}