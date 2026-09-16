rule EquationGroup_Toolset_Apr17_st_lp_RID3418 : APT DEMO EXE FILE {
   meta:
      description = "Detects EquationGroup Tool - April Leak"
      author = "Florian Roth"
      reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
      date = "2017-04-15 15:15:51"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "3b6f756cca096548dcad2b6c241c1dafd16806c060bec82a530f4d38755286a2"
      tags = "APT, DEMO, EXE, FILE"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = "Previous command: set injection processes (status=0x%x)" fullword ascii
      $x2 = "Secondary injection process is <null> [no secondary process will be used]" fullword ascii
      $x3 = "Enter the address to be used as the spoofed IP source address (xxx.xxx.xxx.xxx) -> " fullword ascii
      $x4 = "E: Execute a Command on the Implant" fullword ascii
   condition: 
      ( uint16 ( 0 ) == 0x5a4d and filesize < 300KB and 1 of them )
}