rule sig_20160301_cd9214ac88050e7fbba6aef595ce76cb {
  meta:
    description = "datamaliciousorder - file 20160301_cd9214ac88050e7fbba6aef595ce76cb.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "12688ac9766a0ef00fd6e7ffaebf63a1d7ff13b691a9c0815f7769ef6c4e4e6c"

  strings:
    $s1 = "while (apostropheVariation[(\"\\u0072\\u0065\\u0061\\u0064ys\\u0074a\\u0074\\u0065\")] < ((0 + 1) ^ (5 + 0))) {" fullword ascii
    $s2 = "professionClan = (((17 ^ 33) * 2 * 3 + (37 - 33)), this);" fullword ascii
    $s3 = "    operatorBureau[(\"\\u0072\\u0065\\u0061\\u006c\", \"\\u0067\\u0065n\\u0065r\\u0061t\\u006fr\", \"\\u0061\\u0064\\u0065quat" ascii
    $s4 = "065gu\\u006ca\\u0074\\u0065\", \"w\\u0072\\u0069t\\u0065\")](apostropheVariation[(\"\\u0073\\u0074\\u006f\\u0072m\", function St" ascii
    $s5 = "} catch (dessertRespectable) {};" fullword ascii

  condition:
    uint16(0) == 0x7270 and
    all of them
}