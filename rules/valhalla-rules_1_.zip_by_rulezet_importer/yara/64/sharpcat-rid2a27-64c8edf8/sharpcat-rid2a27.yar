rule SharpCat_RID2A27 : DEMO EXE FILE HKTL {
   meta:
      description = "Detects Hack Tool SharpCat_RID2A27 - file SharpCat_RID2A27.exe"
      author = "Florian Roth"
      reference = "https://github.com/Cn33liz/SharpCat_RID2A27"
      date = "2016-06-10 03:56:41"
      score = 80
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "96dcdf68b06c3609f486f9d560661f4fec9fe329e78bd300ad3e2a9f07e332e9"
      tags = "DEMO, EXE, FILE, HKTL"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = "ShellZz" fullword ascii
      $s2 = "C:\\Windows\\System32\\cmd.exe" fullword wide
      $s3 = "currentDirectory" fullword ascii
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 20KB and all of them
}