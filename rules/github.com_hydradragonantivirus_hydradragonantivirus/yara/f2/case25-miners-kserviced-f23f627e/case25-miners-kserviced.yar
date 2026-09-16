rule case25_miners_kserviced {
  meta:
    description = "miners - file kserviced"
    author      = "Brian Laskowski"
    reference   = "https://github.com/Hestat/lw-yara"
    date        = "2018-08-05"
    hash1       = "6c9b44df7caa65cb7f652f411b38f8b49564e3ae265aa75a2c6d0acda22ea20f"

  strings:
    $s1 = "PROT_EXEC|PROT_WRITE failed." fullword ascii
    $s2 = "40,*###($ " fullword ascii  
    $s3 = "$3D$5D$ '" fullword ascii  
    $s4 = "** HUGE PA" fullword ascii
    $s5 = "RkeyedW;" fullword ascii

  condition:
    (uint16(0) == 0x457f and
      filesize < 1000KB and
      (all of them)
    ) or (all of them)
}