rule SUSP_SFX_RunProgram_WScript_RID3143 : DEMO EXE FILE G0047 SUSP {
   meta:
      description = "Detects suspicious SFX as used by Gamaredon group"
      author = "Florian Roth"
      reference = "Internal Research"
      date = "2018-09-27 13:15:01"
      score = 60
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "e3bb02c5985fc64759b9c2d3c5474d46237ce472b4a0101c6313dafa939de5a9"
      hash2 = "0ecf88d4b32895b4819dec3acb62eaaa7035aa6292499d903f76af60fcec0d6a"
      hash3 = "a7a48f5220bd1ebe04de258d71fdd001711c165d162bd45e8cfbe8964eddf01c"
      tags = "DEMO, EXE, FILE, G0047, SUSP"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = "RunProgram=\"wscript.exe" fullword ascii
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 10000KB and 1 of them
}