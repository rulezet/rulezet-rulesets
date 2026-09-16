rule sig_20160301_e2ac3cc1b2f518110f40273c1123b425 {
  meta:
    description = "datamaliciousorder - file 20160301_e2ac3cc1b2f518110f40273c1123b425.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c3585e3c6cd76e2bd80dab591869086ad61e12155fae226781077a0f7f13c90e"

  strings:
    $s1 = "filterRhombus = illustrateBarbarian[(\"manifest\", \"risk\", \"ExpandEnvironmentStrings\")]((\"storm\", \"organ\", \"progress\"," ascii
    $s2 = "while(infectionRadio[(\"numeral\", \"reaction\", \"individuality\", \"readystate\")] < (([!+[] + !+[]]) * ([!+[] + !+[]]))) {" fullword ascii
    $s3 = "filterRhombus = illustrateBarbarian[(\"manifest\", \"risk\", \"ExpandEnvironmentStrings\")]((\"storm\", \"organ\", \"progress\"," ascii
    $s4 = "graphicEffective = (((([!+[] + !+[]]) * (((([!+[] + !+[] + !+[]])) + \"\" + (([+!+[]])))) * ([!+[] + !+[] + !+[]]) * ([!+[] + !+" ascii
    $s5 = "]) * ([!+[] + !+[]]) * ([!+[] + !+[]] * [!+[] + !+[] + !+[]] - 1) * ([!+[] + !+[]])) / (47 ^ 31)), this);" fullword ascii
    $s6 = "originArctic[(\"reserve\", function String.prototype.primitiveBeach() {" fullword ascii
    $s7 = "} catch(secretAuction) {};" fullword ascii

  condition:
    uint16(0) == 0x7267 and
    all of them
}