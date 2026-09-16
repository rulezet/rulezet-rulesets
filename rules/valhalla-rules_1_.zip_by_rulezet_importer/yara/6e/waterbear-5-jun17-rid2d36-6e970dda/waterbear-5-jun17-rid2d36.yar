rule Waterbear_5_Jun17_RID2D36 : DEMO FILE MAL {
   meta:
      description = "Detects malware from Operation Waterbear"
      author = "Florian Roth"
      reference = "https://www.trendmicro.com/en_us/research/17/f/following-trail-blacktech-cyber-espionage-campaigns.html"
      date = "2017-06-23 10:22:11"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      modified = "2024-07-19"
      hash1 = "d3678cd9744b3aedeba23a03a178be5b82d5f8059a86f816007789a9dd06dc7d"
      tags = "DEMO, FILE, MAL"
      minimum_yara = "3.5.0"
      
   strings:
      $a1 = "ICESWORD" fullword ascii
      $a2 = "klog.dat" fullword ascii
      $s1 = "\\cswbse.dll" ascii
      $s2 = "WIRESHARK" fullword ascii
      $s3 = "default_zz|" fullword ascii
      $s4 = "%c4%u-%.2u-%.2u %.2u:%.2u" fullword ascii
      $s5 = "1111%c%s" fullword ascii
   condition: 
      ( uint16 ( 0 ) == 0x3d53 and filesize < 100KB and ( all of ( $a* ) or 3 of them ) )
}