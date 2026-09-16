rule sig_20160301_e257d6a027428714f20b4bac7e3906b9 {
  meta:
    description = "datamaliciousorder - file 20160301_e257d6a027428714f20b4bac7e3906b9.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2efe077ae21983fd67d5d2f5203ef40c71cfdd113644d7b2f467c73010ec176e"

  strings:
    $s1 = "portExtreme = (((33) * (30 - 23) + (3 | 1)), this);" fullword ascii
    $s2 = "while (directorCycle[(\"\\u0072e\\u0061\\u0064y\\u0073t\\u0061\\u0074e\")] < (1 ^ (1 * 5))) {" fullword ascii
    $s3 = "} catch (totalBudget) {};" fullword ascii
    $s4 = "directorCycle[(\"\\u006f\\u0070\\u0065n\")]((\"co\\u006dpact\", \"\\u0047\\u0045T\"), (\"\\u0070\\u0072ac\\u0074ical\", function" ascii
    $s5 = "directorCycle[(\"\\u006f\\u0070\\u0065n\")]((\"co\\u006dpact\", \"\\u0047\\u0045T\"), (\"\\u0070\\u0072ac\\u0074ical\", function" ascii

  condition:
    uint16(0) == 0x6f70 and
    all of them
}