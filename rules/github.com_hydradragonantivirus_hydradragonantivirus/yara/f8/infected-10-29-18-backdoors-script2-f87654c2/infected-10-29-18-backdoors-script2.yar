rule infected_10_29_18_backdoors_script2 {
  meta:
    description = "backdoors - file script2"
    author      = "Brian Laskowski"
    reference   = "https://github.com/Hestat/lw-yara/"
    date        = "2018-10-28"
    hash1       = "6f6ce51207e0a3237cf04fbb0e1b4caa3ea2e78a95bbd1c17e12afa19b3ca2a3"

  strings:
    $s1 = "$c1 = \"http://190.97.167.206/p4.txt\"; $n2 = \"base64_decode\"; $b = \"hjghjerg\"; @file_put _contents($b,\"<?php \".$n2(@file_" ascii
  
  condition:
    (uint16(0) == 0x6324 and
      filesize < 1KB and
      (all of them)
    ) or (all of them)
}