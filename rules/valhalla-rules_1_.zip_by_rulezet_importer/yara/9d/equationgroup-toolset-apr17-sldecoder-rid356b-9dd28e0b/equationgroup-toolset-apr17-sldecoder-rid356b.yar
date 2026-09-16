rule EquationGroup_Toolset_Apr17_SlDecoder_RID356B : APT DEMO EXE FILE {
   meta:
      description = "Detects EquationGroup Tool - April Leak"
      author = "Florian Roth"
      reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
      date = "2017-04-15 16:12:21"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "b220f51ca56d9f9d7d899fa240d3328535f48184d136013fd808d8835919f9ce"
      tags = "APT, DEMO, EXE, FILE"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = "Error in conversion. SlDecoder.exe <input filename> <output filename> at command line " fullword wide
      $x2 = "KeyLogger_Data" fullword wide
   condition: 
      ( uint16 ( 0 ) == 0x5a4d and filesize < 200KB and 1 of them )
}