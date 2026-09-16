rule APT_EQGRP_hexdump_RID2D2E : APT DEMO FILE SCRIPT {
   meta:
      description = "EQGRP Toolset Firewall - file hexdump.py"
      author = "Florian Roth"
      reference = "Research"
      date = "2016-08-16 10:20:51"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "95a9a6a8de60d3215c1c9f82d2d8b2640b42f5cabdc8b50bd1f4be2ea9d7575a"
      tags = "APT, DEMO, FILE, SCRIPT"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "def hexdump(x,lead=\"[+] \",out=sys.stdout):" fullword ascii
      $s2 = "print >>out, \"%s%04x  \" % (lead,i)," fullword ascii
      $s3 = "print >>out, \"%02X\" % ord(x[i+j])," fullword ascii
      $s4 = "print >>out, sane(x[i:i+16])" fullword ascii
   condition: 
      ( uint16 ( 0 ) == 0x2123 and filesize < 1KB and 2 of ( $s* ) ) or ( all of them )
}