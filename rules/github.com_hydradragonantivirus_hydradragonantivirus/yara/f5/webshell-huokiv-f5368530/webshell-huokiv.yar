rule webshell_huokiv {
  meta:
    description = "PHP - file webshell_huokiv.php"
    author      = "Brian Laskowski"
    reference   = "https://github.com/Hestat/lw-yara/"
    date        = "2019-10-11"
    hash1       = "2c62fa698f2a3afd78aac9a0ec5193b6e92c31c58aabc03925d6b49eab0a5785"

  strings:
    $s1 = "K<=RdpEpKmaDTL:KNImSYLPBipGl,pGo>M8ShIc>0575OmWO0X;0,W=wzN1JTBNj4gW=YT1M+ADlbhzz2s+B5:AQ +OvROVmZ RU lJLb>C=V=ZhP55jzrH - Q>=k4 " ascii

  condition:
    (uint16(0) == 0x3f3c and
      filesize < 4KB and
      (all of them)
    ) or (all of them)
}