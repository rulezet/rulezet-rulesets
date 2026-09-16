rule APT_StuxNet_dll_RID2CCB : APT DEMO EXE FILE stuxnet {
   meta:
      description = "Stuxnet Sample - file dll.dll"
      author = "Florian Roth"
      reference = "Internal Research"
      date = "2016-07-09 10:04:21"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "9e392277f62206098cf794ddebafd2817483cfd57ec03c2e05e7c3c81e72f562"
      tags = "APT, DEMO, EXE, FILE, stuxnet"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "SUCKM3 FROM EXPLORER.EXE MOTH4FUCKA #@!" fullword ascii
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 100KB and $s1
}