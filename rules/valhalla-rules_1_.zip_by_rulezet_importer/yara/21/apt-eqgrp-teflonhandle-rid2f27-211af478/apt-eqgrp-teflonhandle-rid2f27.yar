rule APT_EQGRP_teflonhandle_RID2F27 : APT DEMO EXE FILE {
   meta:
      description = "Detects tool from EQGRP toolset - file teflonhandle.exe"
      author = "Florian Roth"
      reference = "Research"
      date = "2016-08-15 11:45:01"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "APT, DEMO, EXE, FILE"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "%s [infile] [outfile] /k 0x[%i character hex key] </g>" fullword ascii
      $s2 = "File %s already exists.  Overwrite? (y/n) " fullword ascii
      $s3 = "Random Key : 0x" fullword ascii
      $s4 = "done (%i bytes written)." fullword ascii
      $s5 = "%s --> %s..." fullword ascii
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 20KB and 2 of them
}