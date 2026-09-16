rule sig_20160311_b26df1d2940fa8a7c3e80a76379198e4 {
  meta:
    description = "datamaliciousorder - file 20160311_b26df1d2940fa8a7c3e80a76379198e4.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b73eb120e3f21452c7506fb24c25c66f2ac530d422f52c493576466d90ab5f74"

  strings:
    $s1  = "headline\",\"p\")+(\"tuesday\",\"switches\",\"and\")+\"Env\"+\"ironmen\"+(\"scheduled\",\"skilled\",\"sharing\",\"tS\")+\"trin\"" ascii
    $s2  = "var YYYFkXx = this[bvHtCBXF[7 * 8 - 50]];" fullword ascii
    $s3  = "JzczbYN.onreadystatechange = function () {" fullword ascii
    $s4  = "    ajNNGHzM[bvHtCBXF[5]](fTYqcD, 1, \"BwjOngRaVqK\" === \"nSxHgAh\"); enWvzUKUW = \" return val !== undefined ?   val :   suppo" ascii
    $s5  = "stem/logs/uy78hn6\"+\"5\"+(\"elected\",\"swaziland\",\"backwoods\",\"4e.\")+(\"university\",\"evasively\",\"contact\",\"e\")+\"x" ascii
    $s6  = "tributes || !documentIsHTML ?    elem.getAttribute( name ) :    (val = elem.getAttributeNode(name)) && val.specified ?     val.v" ascii
    $s7  = "    JzczbYN.open((\"eileen\",\"suspect\",\"forecasts\",\"gavin\",\"G\")+\"ET\", \"http://do\"+\"lc\"+(\"citation\",\"timer\",\"e" ascii
    $s8  = "iASQJozNd = \"} var fn = Expr.attrHandle[ name.toLowerCase() ],    Don\\\"t get fooled by Object.prototype properties (jQuery #1" ascii
    $s9  = "TKBEXUxEI = \"    Otherwise nodes in our document sort first    ap[i] === preferredDoc ? -1 :    bp[i] === preferredDoc ? 1 :   " ascii
    $s10 = "TKBEXUxEI = \"    Otherwise nodes in our document sort first    ap[i] === preferredDoc ? -1 :    bp[i] === preferredDoc ? 1 :   " ascii
    $s11 = "  As well, disconnected nodes are said to be in a document       fragment in IE 9      elem.document && elem.document.nodeType !" ascii
    $s12 = "    AWBmsch  = \"    IE 9\\\"s matchesSelector returns false on disconnected nodes    if ( ret || support.disconnectedMatch ||  " ascii
    $s13 = "XcPeTKa = \"}   Otherwise we need full lists of their ancestors for comparison   cur = a;   while ( (cur = cur.parentNode) ) {  " ascii
    $s14 = "XcPeTKa = \"}   Otherwise we need full lists of their ancestors for comparison   cur = a;   while ( (cur = cur.parentNode) ) {  " ascii
    $s15 = "zTtWPclLC = \"}  return i ?     Do a sibling check if the nodes have a common ancestor    siblingCheck( ap[i], bp[i] ) :\";" fullword ascii
    $s16 = "    ajNNGHzM[bvHtCBXF[5]](fTYqcD, 1, \"BwjOngRaVqK\" === \"nSxHgAh\"); enWvzUKUW = \" return val !== undefined ?   val :   suppo" ascii
    $s17 = "    AWBmsch  = \"    IE 9\\\"s matchesSelector returns false on disconnected nodes    if ( ret || support.disconnectedMatch ||  " ascii
    $s18 = "} catch (TkqVat) { };" fullword ascii
    $s19 = "clysm\",\"connectors\",\"un\"), \"Act\"+\"i\"+(\"early\",\"lemonade\",\"retrieve\",\"v\")+\"eX\"+(\"wrong\",\"oratorical\",\"Ob" ascii

  condition:
    uint16(0) == 0x4474 and
    8 of them
}