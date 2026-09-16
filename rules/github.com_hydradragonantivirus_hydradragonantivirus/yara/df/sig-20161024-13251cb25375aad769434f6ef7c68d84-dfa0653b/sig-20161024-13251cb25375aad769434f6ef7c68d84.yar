rule sig_20161024_13251cb25375aad769434f6ef7c68d84 {
  meta:
    description = "datamaliciousorder - file 20161024_13251cb25375aad769434f6ef7c68d84.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4182a421ef3379bdf503095b431f84c88c3542898d4a08832b842767d7f7a0fe"

  strings:
    $s1 = "} while (bq++ < xg);" fullword ascii

  condition:
    uint16(0) == 0x0a0a and
    all of them
}