rule RUAG_Tavdig_Malformed_Executable_RID3355 : APT DEMO EXE FILE {
   meta:
      description = "Detects an embedded executable with a malformed header - known from Tavdig malware"
      author = "Florian Roth"
      reference = "https://www.ncsc.admin.ch/govcert"
      date = "2016-05-23 14:43:21"
      score = 60
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      modified = "2024-07-19"
      tags = "APT, DEMO, EXE, FILE"
      minimum_yara = "3.5.0"
      
   condition: 
      uint16 ( 0 ) == 0x5a4d and uint32 ( uint32 ( 0x3C ) ) == 0x0000AD0B
}