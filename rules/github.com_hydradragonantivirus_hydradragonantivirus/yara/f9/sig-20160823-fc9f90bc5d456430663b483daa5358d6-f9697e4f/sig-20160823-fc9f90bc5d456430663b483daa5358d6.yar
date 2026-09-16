rule sig_20160823_fc9f90bc5d456430663b483daa5358d6 {
  meta:
    description = "datamaliciousorder - file 20160823_fc9f90bc5d456430663b483daa5358d6.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "78fa0c47e8caca1b30335754f157438b37f986aaf3a2f9701ee2a5b894d538a6"

  strings:
    $s1 = "var Cp = new Array(\"\\x76\",\"\\x61\",\"\\x72\",\"\\x20\",\"\\x5f\",\"\\x77\",\"\\x73\",\"\\x63\",\"\\x69\",\"\\x70\",\"\\x74\"" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}