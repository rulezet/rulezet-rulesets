rule sig_20161024_8c61d2843c2cca5ac0f032122b586f15 {
  meta:
    description = "datamaliciousorder - file 20161024_8c61d2843c2cca5ac0f032122b586f15.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "eac070fcd5f0125b86b99ea0a8fa2c53f3efd40d475163d9a93fd7c47c7ea712"

  strings:
    $s1 = "} while (qc++ < wk);" fullword ascii

  condition:
    uint16(0) == 0x0a0a and
    all of them
}