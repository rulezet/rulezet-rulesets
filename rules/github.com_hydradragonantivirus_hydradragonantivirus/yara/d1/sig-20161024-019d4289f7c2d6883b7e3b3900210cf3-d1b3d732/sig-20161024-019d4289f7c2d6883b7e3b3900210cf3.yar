rule sig_20161024_019d4289f7c2d6883b7e3b3900210cf3 {
  meta:
    description = "datamaliciousorder - file 20161024_019d4289f7c2d6883b7e3b3900210cf3.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "81c0e791173fdd76971d405b4d4228ec3c19e62bf8aae1a712014bbde219abd0"

  strings:
    $s1 = "} while (ze++ < md);" fullword ascii

  condition:
    uint16(0) == 0x0a0a and
    all of them
}