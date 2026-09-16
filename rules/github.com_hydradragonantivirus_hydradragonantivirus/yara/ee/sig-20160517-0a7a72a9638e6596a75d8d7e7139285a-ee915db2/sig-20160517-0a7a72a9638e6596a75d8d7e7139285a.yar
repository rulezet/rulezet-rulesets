rule sig_20160517_0a7a72a9638e6596a75d8d7e7139285a {
  meta:
    description = "datamaliciousorder - file 20160517_0a7a72a9638e6596a75d8d7e7139285a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e3312c4cf01d47d713f5c269de6759e70a7f52436bdb3c0c4f22f2fa7aeaff4e"

  strings:
    $s1  = "jaguar = jaguar+ alumni.shift();" fullword ascii
    $s2  = "strategy = ((\"pebble\", \"nomad\", \"selfsatisfied\", \"regal\", \"sYKwXmARU\") + \"sySMzvsy\").regulatory2();" fullword ascii
    $s3  = "String.prototype.regulatory4 = function() {" fullword ascii
    $s4  = "String.prototype.regulatory = function () {" fullword ascii
    $s5  = "var thermal = alumni.pop().split(\"" fullword ascii
    $s6  = "String.prototype.regulatory2 = function () {" fullword ascii
    $s7  = "        reasons[(changes + \"o\"+(\"gloaming\",\"exalting\",\"domestication\",\"republic\",\"loudness\",\"relationship\",\"terro" ascii
    $s8  = "armed = \"_F2_\";" fullword ascii
    $s9  = "topped = this;" fullword ascii
    $s10 = "var elopement = 0;" fullword ascii
    $s11 = "orts, false);" fullword ascii
    $s12 = "  declivity = [];" fullword ascii
    $s13 = "var lying = 6/6;" fullword ascii
    $s14 = "weasel = ((\"states\", \"chose\", \"grammatical\", \"amended\", \"ESrsUfL\") + \"CpDEyuqPiXF\").regulatory2();" fullword ascii
    $s15 = "washing = \"b3Blbg==\".regulatory4();;" fullword ascii
    $s16 = "py\",\"promulgation\",\"specify\",\"strategic\",\"samurai\",\"global\",\"08\"), strategy)] = 0;" fullword ascii
    $s17 = "twentynine[alumni.shift()](jaguar, lying, true);WKTiLaaJFjS = \"_F17_\";" fullword ascii
    $s18 = "for (var i in tucson){topped = topped.replace(i, tucson[i]);}" fullword ascii
    $s19 = "var asthma = \"QWinformedN0aXZinformedlWE9iainformedmVjdA=informed=\".regulatory4();" fullword ascii
    $s20 = "function responses(sorts, errant) {" fullword ascii

  condition:
    uint16(0) == 0x6c4b and
    8 of them
}