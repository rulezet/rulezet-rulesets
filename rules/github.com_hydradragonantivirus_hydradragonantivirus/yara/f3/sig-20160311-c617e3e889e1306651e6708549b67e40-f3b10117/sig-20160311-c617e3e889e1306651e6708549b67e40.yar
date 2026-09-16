rule sig_20160311_c617e3e889e1306651e6708549b67e40 {
  meta:
    description = "datamaliciousorder - file 20160311_c617e3e889e1306651e6708549b67e40.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "18d2425f196b35a61a2d0286ce034506ba9b6fa2ee0c3a730d5f706b3a6b2723"

  strings:
    $x1  = "    qcKMpt.open(\"G\"+(\"perversion\",\"rhetorical\",\"ET\"), (\"anthropology\",\"garage\",\"htt\")+(\"broach\",\"dramatist\",\"" ascii
    $s2  = "var jzKvFrqT = this[yFzByCj[7 * 8 - 50]];" fullword ascii
    $s3  = "    Fhzdkr[yFzByCj[5]](XjybQr, 1, \"YQzkDrbiQ\" === \"pMXmKQtimUo\"); ttTDaA = \" return val !== undefined ?   val :   support.a" ascii
    $s4  = "qcKMpt.onreadystatechange = function () {" fullword ascii
    $s5  = "utes || !documentIsHTML ?    elem.getAttribute( name ) :    (val = elem.getAttributeNode(name)) && val.specified ?     val.value" ascii
    $s6  = "VVsNTDb = \"    Otherwise nodes in our document sort first    ap[i] === preferredDoc ? -1 :    bp[i] === preferredDoc ? 1 :    0" ascii
    $s7  = "VVsNTDb = \"    Otherwise nodes in our document sort first    ap[i] === preferredDoc ? -1 :    bp[i] === preferredDoc ? 1 :    0" ascii
    $s8  = "IRYJRh = \"} var fn = Expr.attrHandle[ name.toLowerCase() ],    Don\\\"t get fooled by Object.prototype properties (jQuery #1380" ascii
    $s9  = "      As well, disconnected nodes are said to be in a document       fragment in IE 9      elem.document && elem.document.nodeTy" ascii
    $s10 = "    Fhzdkr[yFzByCj[5]](XjybQr, 1, \"YQzkDrbiQ\" === \"pMXmKQtimUo\"); ttTDaA = \" return val !== undefined ?   val :   support.a" ascii
    $s11 = "blOYtbSRT = \"}   Otherwise we need full lists of their ancestors for comparison   cur = a;   while ( (cur = cur.parentNode) ) {" ascii
    $s12 = "blOYtbSRT = \"}   Otherwise we need full lists of their ancestors for comparison   cur = a;   while ( (cur = cur.parentNode) ) {" ascii
    $s13 = "    pnkQRHFtbEU  = \"    IE 9\\\"s matchesSelector returns false on disconnected nodes    if ( ret || support.disconnectedMatch " ascii
    $s14 = "uTMMpklxWD = \"}  return i ?     Do a sibling check if the nodes have a common ancestor    siblingCheck( ap[i], bp[i] ) :\";" fullword ascii
    $s15 = "    pnkQRHFtbEU  = \"    IE 9\\\"s matchesSelector returns false on disconnected nodes    if ( ret || support.disconnectedMatch " ascii
    $s16 = "} catch (qGaAtgSQ) { };" fullword ascii

  condition:
    uint16(0) == 0x5367 and
    1 of ($x*) and 4 of them
}