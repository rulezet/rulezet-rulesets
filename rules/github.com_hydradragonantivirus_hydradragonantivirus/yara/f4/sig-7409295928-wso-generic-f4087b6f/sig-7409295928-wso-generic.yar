rule sig_7409295928_WSO_generic {
  meta:
    description = "case135 - file 7409295928.php"
    author      = "Brian Laskowski"
    reference   = "https://github.com/Hestat/lw-yara"
    date        = "2018-06-15"
    hash1       = "b97d6507049bcde47cbe0666675abdb7159a519cbbe5fe97c282f4d6f9d59c16"

  strings:
    $s1 = "?php" ascii
    $s2 = "WSO" ascii
    $s3 = "urldecode" ascii
        $s5 = "$GLOBALS" ascii

  condition:
    (uint16(0) == 0x3f3c and
      filesize < 300KB and
      (all of them)
    ) or (all of them)
}