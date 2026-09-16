rule sig_20161024_9bf43d9b39896e679d117faf5b9e28b3 {
  meta:
    description = "datamaliciousorder - file 20161024_9bf43d9b39896e679d117faf5b9e28b3.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "44bc621859fd1622f04aefbdf7aadb8053a5fae939a7e0bcecb4c1092e46cee0"

  strings:
    $s1 = "} while (jn++ < nh);" fullword ascii

  condition:
    uint16(0) == 0x0a0a and
    all of them
}