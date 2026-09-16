rule sig_20161024_c2230f8ac38f5198eeee406745e021f3 {
  meta:
    description = "datamaliciousorder - file 20161024_c2230f8ac38f5198eeee406745e021f3.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9b3d9a2c1341f8fcd72a707e82b08dde268a86f099f928ca4ff055a0dcdec214"

  strings:
    $s1 = "} while (us++ < rm);" fullword ascii

  condition:
    uint16(0) == 0x0a0a and
    all of them
}