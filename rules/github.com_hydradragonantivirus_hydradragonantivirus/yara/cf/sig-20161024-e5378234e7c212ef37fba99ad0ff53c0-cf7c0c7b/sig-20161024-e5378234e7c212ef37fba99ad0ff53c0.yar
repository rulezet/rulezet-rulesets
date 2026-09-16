rule sig_20161024_e5378234e7c212ef37fba99ad0ff53c0 {
  meta:
    description = "datamaliciousorder - file 20161024_e5378234e7c212ef37fba99ad0ff53c0.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "79451b4a0d0b5263e1cc154856f250ded5736f5ef80bdfcf5a852b721ac6e43d"

  strings:
    $s1 = "} while (yr++ < zj);" fullword ascii

  condition:
    uint16(0) == 0x0a0a and
    all of them
}