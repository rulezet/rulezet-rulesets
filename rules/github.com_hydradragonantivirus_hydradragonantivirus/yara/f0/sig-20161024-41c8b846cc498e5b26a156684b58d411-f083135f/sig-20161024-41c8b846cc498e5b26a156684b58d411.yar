rule sig_20161024_41c8b846cc498e5b26a156684b58d411 {
  meta:
    description = "datamaliciousorder - file 20161024_41c8b846cc498e5b26a156684b58d411.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "161f855d9e97c50275be4ef5ace57999124da4ee2df4cefd4b682ed1344e6497"

  strings:
    $s1 = "} while (jm++ < vi0);" fullword ascii

  condition:
    uint16(0) == 0x0a0a and
    all of them
}