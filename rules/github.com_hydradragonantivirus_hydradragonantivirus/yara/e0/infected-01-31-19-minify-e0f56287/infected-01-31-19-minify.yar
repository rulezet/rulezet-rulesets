rule infected_01_31_19_minify {
  meta:
    description = "01-31-19 - file minify.php"
    author      = "Brian Laskowski"
    reference   = "https://github.com/Hestat/lw-yara/"
    date        = "2019-01-31"
    hash1       = "48dee7233033b71174a063d1241754aa493ac33cd6f47487d130ed2a117f3856"

  strings:
    $s1 = "function mc($OQ,$Ba)" fullword ascii
    $s2 = "$AP=\"f152ff3d0236535f1a5feb9272731e47\";" fullword ascii
    $s3 = "<?php"

  condition:
    (uint16(0) == 0x3f3c and
      filesize < 90KB and
      (all of them)
    ) or (all of them)
}