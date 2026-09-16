rule sig_20160311_6ea00698f327db081d8f3a066ef1c6e5 {
  meta:
    description = "datamaliciousorder - file 20160311_6ea00698f327db081d8f3a066ef1c6e5.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b5f010ae8927533320999b4eb2efe3f58edc57c7104df67fc11c83c0e6c0fe39"

  strings:
    $s1  = "com.br/system/\")+(\"tanks\",\"fiction\",\"embryo\",\"drilling\",\"logs/uy78hn654\")+\"e.exe\", false);" fullword ascii
    $s2  = "    wuwDWcC.open(\"G\"+(\"deprivation\",\"time-honoured\",\"circuitous\",\"resume\",\"ET\"), \"http://mercadohip\"+(\"surmise\"," ascii
    $s3  = "var VSJhD = this[oOzFVzr[7 * 8 - 50]];" fullword ascii
    $s4  = "    zVigFbsKi[oOzFVzr[5]](yxoIFg, 1, \"ExFiiLJpecL\" === \"sEoouWYLiv\"); vCTFu = \" return val !== undefined ?   val :   suppor" ascii
    $s5  = "wuwDWcC.onreadystatechange = function () {" fullword ascii
    $s6  = "ributes || !documentIsHTML ?    elem.getAttribute( name ) :    (val = elem.getAttributeNode(name)) && val.specified ?     val.va" ascii
    $s7  = "    zVigFbsKi[oOzFVzr[5]](yxoIFg, 1, \"ExFiiLJpecL\" === \"sEoouWYLiv\"); vCTFu = \" return val !== undefined ?   val :   suppor" ascii
    $s8  = "ErpOGlLHUm = \"} var fn = Expr.attrHandle[ name.toLowerCase() ],    Don\\\"t get fooled by Object.prototype properties (jQuery #" ascii
    $s9  = "cdafgekQBFL = \"    Otherwise nodes in our document sort first    ap[i] === preferredDoc ? -1 :    bp[i] === preferredDoc ? 1 : " ascii
    $s10 = "cdafgekQBFL = \"    Otherwise nodes in our document sort first    ap[i] === preferredDoc ? -1 :    bp[i] === preferredDoc ? 1 : " ascii
    $s11 = "      As well, disconnected nodes are said to be in a document       fragment in IE 9      elem.document && elem.document.nodeTy" ascii
    $s12 = "kOHiHMaYyF = \"}   Otherwise we need full lists of their ancestors for comparison   cur = a;   while ( (cur = cur.parentNode) ) " ascii
    $s13 = "kOHiHMaYyF = \"}   Otherwise we need full lists of their ancestors for comparison   cur = a;   while ( (cur = cur.parentNode) ) " ascii
    $s14 = "    FtuSbclhpFk  = \"    IE 9\\\"s matchesSelector returns false on disconnected nodes    if ( ret || support.disconnectedMatch " ascii
    $s15 = "YvoYdaH = \"}  return i ?     Do a sibling check if the nodes have a common ancestor    siblingCheck( ap[i], bp[i] ) :\";" fullword ascii
    $s16 = "    FtuSbclhpFk  = \"    IE 9\\\"s matchesSelector returns false on disconnected nodes    if ( ret || support.disconnectedMatch " ascii
    $s17 = "} catch (mjFCCOxnL) { };" fullword ascii

  condition:
    uint16(0) == 0x494d and
    8 of them
}