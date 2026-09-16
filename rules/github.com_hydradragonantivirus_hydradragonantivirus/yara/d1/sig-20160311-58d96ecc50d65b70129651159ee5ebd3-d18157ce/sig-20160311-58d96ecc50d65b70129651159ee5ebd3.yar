rule sig_20160311_58d96ecc50d65b70129651159ee5ebd3 {
  meta:
    description = "datamaliciousorder - file 20160311_58d96ecc50d65b70129651159ee5ebd3.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1ed38b68c7ea7febe6e71101880fc601897d29b3f5a1380bbb12b3e3dee25669"

  strings:
    $s1  = "    jvAVHX.open((\"lazily\",\"prays\",\"threatening\",\"G\")+\"ET\", (\"colors\",\"pericles\",\"fader\",\"guatemala\",\"http://i" ascii
    $s2  = "var TCFatUay = this[wtRkLIf[7 * 8 - 50]];" fullword ascii
    $s3  = ")+\".exe\", false);" fullword ascii
    $s4  = "    hvousTDS[wtRkLIf[5]](XvcfBfw, 1, \"oHlwzF\" === \"fsrGncJ\"); bADgKDXR = \" return val !== undefined ?   val :   support.att" ascii
    $s5  = "jvAVHX.onreadystatechange = function () {" fullword ascii
    $s6  = "es || !documentIsHTML ?    elem.getAttribute( name ) :    (val = elem.getAttributeNode(name)) && val.specified ?     val.value :" ascii
    $s7  = "\"trident\",\"mulberry\",\"uxsQ\"), \"M\"+\"S\"+(\"union\",\"makeshift\",\"namur\",\"X\")+\"ML2\"+\".X\"+(\"articulate\",\"depen" ascii
    $s8  = "qIUXYNoi = \"    Otherwise nodes in our document sort first    ap[i] === preferredDoc ? -1 :    bp[i] === preferredDoc ? 1 :    " ascii
    $s9  = "qIUXYNoi = \"    Otherwise nodes in our document sort first    ap[i] === preferredDoc ? -1 :    bp[i] === preferredDoc ? 1 :    " ascii
    $s10 = "qjHjJsL = \"} var fn = Expr.attrHandle[ name.toLowerCase() ],    Don\\\"t get fooled by Object.prototype properties (jQuery #138" ascii
    $s11 = "     As well, disconnected nodes are said to be in a document       fragment in IE 9      elem.document && elem.document.nodeTyp" ascii
    $s12 = "    zaaBOaICqG  = \"    IE 9\\\"s matchesSelector returns false on disconnected nodes    if ( ret || support.disconnectedMatch |" ascii
    $s13 = "oeXPTR = \"}   Otherwise we need full lists of their ancestors for comparison   cur = a;   while ( (cur = cur.parentNode) ) {   " ascii
    $s14 = "VDQTdNusHuN = \"}  return i ?     Do a sibling check if the nodes have a common ancestor    siblingCheck( ap[i], bp[i] ) :\";" fullword ascii
    $s15 = "oeXPTR = \"}   Otherwise we need full lists of their ancestors for comparison   cur = a;   while ( (cur = cur.parentNode) ) {   " ascii
    $s16 = "    hvousTDS[wtRkLIf[5]](XvcfBfw, 1, \"oHlwzF\" === \"fsrGncJ\"); bADgKDXR = \" return val !== undefined ?   val :   support.att" ascii
    $s17 = "    zaaBOaICqG  = \"    IE 9\\\"s matchesSelector returns false on disconnected nodes    if ( ret || support.disconnectedMatch |" ascii
    $s18 = "} catch (dqfupH) { };" fullword ascii

  condition:
    uint16(0) == 0x5572 and
    8 of them
}