rule sig_20161024_68b4de9ed41e4b02e11616ff89b1f299 {
  meta:
    description = "datamaliciousorder - file 20161024_68b4de9ed41e4b02e11616ff89b1f299.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "73e94bf0872df5b51076e10f88fdcbea4ec45530d7228b6c0153c227a4ae4d78"

  strings:
    $s1 = "} while (hj++ < vw);" fullword ascii

  condition:
    uint16(0) == 0x0a0a and
    all of them
}