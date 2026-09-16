rule infected_08_23_18_citi_phish_INDPBANK_hostname_check {
  meta:
    description = "phishing - file hostname_check.php"
    author      = "Brian Laskowski"
    reference   = "https://github.com/Hestat/lw-yara/"
    date        = "2018-08-23"
    hash1       = "346d452c73b5f477c106db4adf4898c013b2a09ed2d9ac751b6c82d07a33d409"

  strings:
    $s1 = "$hostname = gethostbyaddr($_SERVER['REMOTE_ADDR']); //Get User Hostname" fullword ascii
    $s2 = "header(\"HTTP/1.0 404 Not Found\");" fullword ascii
    $s3 = "if (substr_count($hostname, $word) > 0) {" fullword ascii
    $s4 = "die(\"<h1>404 Not Found</h1>The page that you have requested could not be found.\");" fullword ascii

  condition:
    (uint16(0) == 0x3f3c and
      filesize < 1KB and
      (all of them)
    ) or (all of them)
}