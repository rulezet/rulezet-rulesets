rule sig_20160523_b607f347ed194d7036c9c7be5168edc6 {
  meta:
    description = "datamaliciousorder - file 20160523_b607f347ed194d7036c9c7be5168edc6.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e7e2569a2f8002bebcce3a97bf3c679a4a891f67691beb7e82ce21156a99bfa1"

  strings:
    $s1 = "join('');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}