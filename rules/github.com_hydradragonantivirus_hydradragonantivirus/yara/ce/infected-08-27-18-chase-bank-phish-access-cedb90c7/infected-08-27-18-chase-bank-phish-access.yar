rule infected_08_27_18_chase_bank_phish_access {
  meta:
    description = "chase - file access.php"
    author      = "Brian Laskowski"
    reference   = "https://github.com/Hestat/lw-yara/"
    date        = "2018-08-27"
    hash1       = "2bfe60be990c045955c439f2e22b8aa0fe2393ea79b82a38abf38cd5fcf04c62"

  strings:
    $s1 = "header(\"Location:  https://chaseonline.chase.com/Logon.aspx?LOB=RBGLogon\");" fullword ascii
    $s2 = "$recipient =" fullword ascii
    $s3 = "$message .= \"Email Password              : \".$_POST['emailpassx'].\"\\n\";" fullword ascii
    $s4 = "$message .= \"Email Address             : \".$_POST['emailxnx'].\"\\n\";" fullword ascii
    $s5 = "$ip = getenv(\"REMOTE_ADDR\");" fullword ascii
    $s6 = "$message .= \"---- : || tHAnks tO Phish || :------\\n\";" fullword ascii

  condition:
    (uint16(0) == 0x3f3c and
      filesize < 1KB and
      (all of them)
    ) or (all of them)
}