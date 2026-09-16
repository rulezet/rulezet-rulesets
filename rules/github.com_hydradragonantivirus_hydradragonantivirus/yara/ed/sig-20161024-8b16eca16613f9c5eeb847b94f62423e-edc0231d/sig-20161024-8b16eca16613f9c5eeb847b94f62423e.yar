rule sig_20161024_8b16eca16613f9c5eeb847b94f62423e {
  meta:
    description = "datamaliciousorder - file 20161024_8b16eca16613f9c5eeb847b94f62423e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f145166a0eaeff88bebdc728d48dac6e4d980c43c01f5e03daf9729fb179b496"

  strings:
    $s1 = "} while (hp++ < mk);" fullword ascii

  condition:
    uint16(0) == 0x0a0a and
    all of them
}