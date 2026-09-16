rule sig_20170408_4eafcdb770a1f045af43a9b3d4705acb {
  meta:
    description = "datamaliciousorder - file 20170408_4eafcdb770a1f045af43a9b3d4705acb.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4c4d84f41bc4f76911b90bd31184e757eef4ae77a34106bf3fec1bb4c1cc32e3"

  strings:
    $s1 = "var rima = 500;" fullword ascii
    $s2 = "function ataaa(ziyter) {eval(ziyter);}" fullword ascii
    $s3 = "function muhter(kjg, lki) {return kjg.split(lki);}" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}