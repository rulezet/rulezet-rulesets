rule SUSP_MyWScript_RID2C4D : DEMO EXE FILE MAL SUSP {
   meta:
      description = "Detects files generated with Script2Exe"
      author = "Florian Roth"
      reference = "Internal Research"
      date = "2017-07-27 09:43:21"
      score = 60
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "515f5188ba6d039b8c38f60d3d868fa9c9726e144f593066490c7c97bf5090c8"
      tags = "DEMO, EXE, FILE, MAL, SUSP"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = "C:\\Projets\\vbsedit_source\\script2exe\\Release\\mywscript.pdb" fullword ascii
      $s1 = "mywscript2" fullword wide
      $s2 = "MYWSCRIPT2" fullword wide
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 800KB and ( $x1 or 2 of them )
}