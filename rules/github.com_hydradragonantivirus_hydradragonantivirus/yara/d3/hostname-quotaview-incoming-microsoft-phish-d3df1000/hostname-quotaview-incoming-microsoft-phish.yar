rule hostname_quotaview_incoming_microsoft_phish {
  meta:
    description = "microsoft-phish - file hostname.php"
    author      = "Brian Laskowski"
    reference   = "https://github.com/Hestat/lw-yara"
    date        = "2018-08-11"
    hash1       = "b81fb37dc48812f6ad61984ecf2a8dbbfe581120257cb4becad5375a12e755bb"

  strings:
    $s1 = "$hostname = gethostbyaddr($_SERVER['REMOTE_ADDR']); //Get User Hostname" fullword ascii
    $s2 = "* hostname.php" fullword ascii
    $s3 = "header(\"HTTP/1.0 404 Not Found\");" fullword ascii
    $s4 = "if (substr_count($hostname, $word) > 0) {" fullword ascii
    $s5 = "die(\"<h1>404 Not Found</h1>The page that you have requested could not be found.\");" fullword ascii

  condition:
    (uint16(0) == 0x3f3c and
      filesize < 1KB and
      (all of them)
    ) or (all of them)
}