rule whosthere_alt_pth_RID2E35 : APT DEMO EXE FILE T1550_002 {
   meta:
      description = "Semiautomatically generated YARA rule - file pth.dll"
      author = "Florian Roth"
      reference = "http://www.coresecurity.com/corelabs-research/open-source-tools/pass-hash-toolkit"
      date = "2015-07-10 11:04:41"
      score = 80
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "APT, DEMO, EXE, FILE, T1550_002"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "c:\\debug.txt" fullword ascii
      $s1 = "pth.dll" fullword ascii
      $s2 = "\"Primary\" string found at %.8Xh" fullword ascii
      $s3 = "\"Primary\" string not found!" fullword ascii
      $s4 = "segment 1 found at %.8Xh" fullword ascii
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 240KB and 4 of them
}