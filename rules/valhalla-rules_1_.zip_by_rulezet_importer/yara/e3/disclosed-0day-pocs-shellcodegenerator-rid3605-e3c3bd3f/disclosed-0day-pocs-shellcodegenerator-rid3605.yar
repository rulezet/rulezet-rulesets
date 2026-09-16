rule Disclosed_0day_POCs_shellcodegenerator_RID3605 : DEMO EXE FILE HKTL {
   meta:
      description = "Detects POC code from disclosed 0day hacktool set"
      author = "Florian Roth"
      reference = "Disclosed 0day Repos"
      date = "2017-07-07 16:38:01"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "55c4073bf8d38df7d392aebf9aed2304109d92229971ffac6e1c448986a87916"
      tags = "DEMO, EXE, FILE, HKTL"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = "\\Release\\shellcodegenerator.pdb" ascii
   condition: 
      ( uint16 ( 0 ) == 0x5a4d and filesize < 40KB and all of them )
}