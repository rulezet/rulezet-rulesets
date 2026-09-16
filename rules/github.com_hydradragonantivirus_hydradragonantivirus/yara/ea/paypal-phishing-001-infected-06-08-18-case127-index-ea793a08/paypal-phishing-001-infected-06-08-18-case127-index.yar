rule PAYPAL_PHISHING_001_infected_06_08_18_case127_index {
  meta:
    description = "case127 - file index.php"
    author      = "Brian Laskowski"
    reference   = "https://github.com/Hestat/lw-yara"
    date        = "2018-06-08"
    hash1       = "f2b3619d83488866c194527d707cdbd182baa72e1b35c668fd031284ee8a3862"

  strings:
    $s1 = "fwrite($file,$ip.\" || \".gmdate (\"Y-n-d\").\" ----> \".gmdate (\"H:i:s\").\"\\n\");" fullword ascii
    $s2 = "$ip = getenv(\"REMOTE_ADDR\");" fullword ascii
    $s3 = "$file = fopen(\"drspam.txt\",\"a\");" fullword ascii
    $s4 = "while(false !== ( $file = readdir($dir)) ) {" fullword ascii

  condition:
    (uint16(0) == 0x3f3c and
      filesize < 1KB and
      (all of them)
    ) or (all of them)
}