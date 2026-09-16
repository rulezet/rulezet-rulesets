rule infected_02_22_19_fljm {
  meta:
    description = "02-22-19 - file fljm.php"
    author      = "Brian Laskowski"
    reference   = "https://github.com/Hestat/lw-yara/"
    date        = "2019-02-22"
    hash1       = "1c27a38537e44aea98db227207d904eefb868d0a82034b53be7b76f535371dc6"

  strings:
    $s1 = "str_replace(\"j\",\"\",\"sjtrj_jrjejpljajcje\")" ascii
    $s2 = "<?php"
    $s3 = "(\"i\", \"\", \"ibiaisie6i4i_dieicoide\");"

  condition:
    (uint16(0) == 0x3f3c and
      filesize < 20KB and
      (2 of them)
    ) or (all of them)
}