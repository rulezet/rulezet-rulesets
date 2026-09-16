rule sig_20160525_63122a80157960c2f36640385649379f {
  meta:
    description = "datamaliciousorder - file 20160525_63122a80157960c2f36640385649379f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "17aa4281a4e19f1a3857119952305354f3ec305a996980a3117888a84bc59dc0"

  strings:
    $s1 = "loca rav" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}