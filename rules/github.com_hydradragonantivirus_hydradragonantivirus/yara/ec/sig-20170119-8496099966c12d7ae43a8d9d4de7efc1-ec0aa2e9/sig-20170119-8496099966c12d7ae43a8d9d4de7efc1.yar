rule sig_20170119_8496099966c12d7ae43a8d9d4de7efc1 {
  meta:
    description = "datamaliciousorder - file 20170119_8496099966c12d7ae43a8d9d4de7efc1.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a1f57610e48b37d0079655dc2201e5f9788bffa47b1e02fd245114f01d11151d"

  strings:
    $s1 = "var ictutukpicp2 = new Function(atripdexdyfubvyvboklonbyvonevvitwatfezfuxdyzmonkoxwirzuwyqbezinimyzomylvopjytuticunywcahcepezawp" ascii
    $s2 = "var ictutukpicp2 = new Function(atripdexdyfubvyvboklonbyvonevvitwatfezfuxdyzmonkoxwirzuwyqbezinimyzomylvopjytuticunywcahcepezawp" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}