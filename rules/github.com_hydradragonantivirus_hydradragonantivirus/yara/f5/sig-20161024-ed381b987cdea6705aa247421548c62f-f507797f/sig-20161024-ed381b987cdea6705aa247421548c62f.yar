rule sig_20161024_ed381b987cdea6705aa247421548c62f {
  meta:
    description = "datamaliciousorder - file 20161024_ed381b987cdea6705aa247421548c62f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d6f836c5b5b5934bc822bca4e4ddcda1940f32113cc7128c75f5f916f089a0b4"

  strings:
    $s1 = "} while (ug++ < lc);" fullword ascii

  condition:
    uint16(0) == 0x0a0a and
    all of them
}