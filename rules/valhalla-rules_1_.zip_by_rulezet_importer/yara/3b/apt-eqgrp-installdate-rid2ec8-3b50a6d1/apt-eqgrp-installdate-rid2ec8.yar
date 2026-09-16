rule APT_EQGRP_installdate_RID2EC8 : APT DEMO {
   meta:
      description = "Detects tool from EQGRP toolset - file installdate.pl"
      author = "Florian Roth"
      reference = "Research"
      date = "2016-08-15 11:29:11"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "APT, DEMO"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = "#Provide hex or EP log as command-line argument or as input" fullword ascii
      $x2 = "print \"Gimme hex: \";" fullword ascii
      $x3 = "if ($line =~ /Reg_Dword:  (\\d\\d:\\d\\d:\\d\\d.\\d+ \\d+ - )?(\\S*)/) {" fullword ascii
      $s1 = "if ($_ =~ /InstallDate/) {" fullword ascii
      $s2 = "if (not($cmdInput)) {" fullword ascii
      $s3 = "print \"$hex in decimal=$dec\\n\\n\";" fullword ascii
   condition: 
      filesize < 2KB and ( 1 of ( $x* ) or 3 of them )
}