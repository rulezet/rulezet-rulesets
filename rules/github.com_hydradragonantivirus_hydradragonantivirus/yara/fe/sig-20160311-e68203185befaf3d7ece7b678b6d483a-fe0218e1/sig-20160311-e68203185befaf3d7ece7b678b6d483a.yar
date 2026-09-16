rule sig_20160311_e68203185befaf3d7ece7b678b6d483a {
  meta:
    description = "datamaliciousorder - file 20160311_e68203185befaf3d7ece7b678b6d483a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "95ea017c8ac8f0ca19b25dc8f406f951f43a08771f116e1beaf89b6fbba106e9"

  strings:
    $s1  = "ard\",\"headphones\",\"S\")+(\"kerosene\",\"sausage\",\"formatting\",\"though\",\"t\")+(\"planned\",\"introduces\",\"beaver\",\"" ascii
    $s2  = "var dcTaNOV = this[mwsIco[7 * 8 - 50]];" fullword ascii
    $s3  = "    ltAiLSd.open((\"abner\",\"constructing\",\"G\")+\"ET\", \"http:/\"+\"/\"+\"cherryuk\"+(\"pumpkin\",\"eastwards\",\"convergen" ascii
    $s4  = "\",\"fragile\",\"bison\",\"654e.exe\"), false);" fullword ascii
    $s5  = "    kaidbExUF[mwsIco[5]](UrWHnheWM, 1, \"wGfOntwhSv\" === \"bMTJnixothY\"); zaqiBAdhH = \" return val !== undefined ?   val :   " ascii
    $s6  = "ltAiLSd.onreadystatechange = function () {" fullword ascii
    $s7  = "rt.attributes || !documentIsHTML ?    elem.getAttribute( name ) :    (val = elem.getAttributeNode(name)) && val.specified ?     " ascii
    $s8  = "UkQMQfg = \"    Otherwise nodes in our document sort first    ap[i] === preferredDoc ? -1 :    bp[i] === preferredDoc ? 1 :    0" ascii
    $s9  = "UkQMQfg = \"    Otherwise nodes in our document sort first    ap[i] === preferredDoc ? -1 :    bp[i] === preferredDoc ? 1 :    0" ascii
    $s10 = "yySHoB = \"} var fn = Expr.attrHandle[ name.toLowerCase() ],    Don\\\"t get fooled by Object.prototype properties (jQuery #1380" ascii
    $s11 = " As well, disconnected nodes are said to be in a document       fragment in IE 9      elem.document && elem.document.nodeType !=" ascii
    $s12 = "xuvWLR = \"}   Otherwise we need full lists of their ancestors for comparison   cur = a;   while ( (cur = cur.parentNode) ) {   " ascii
    $s13 = "val.value :     null; };\";" fullword ascii
    $s14 = "    kstTdx  = \"    IE 9\\\"s matchesSelector returns false on disconnected nodes    if ( ret || support.disconnectedMatch ||   " ascii
    $s15 = "xuvWLR = \"}   Otherwise we need full lists of their ancestors for comparison   cur = a;   while ( (cur = cur.parentNode) ) {   " ascii
    $s16 = "ukHjKrNlRa = \"}  return i ?     Do a sibling check if the nodes have a common ancestor    siblingCheck( ap[i], bp[i] ) :\";" fullword ascii
    $s17 = "    kstTdx  = \"    IE 9\\\"s matchesSelector returns false on disconnected nodes    if ( ret || support.disconnectedMatch ||   " ascii
    $s18 = "} catch (OLUPbAM) { };" fullword ascii

  condition:
    uint16(0) == 0x6166 and
    8 of them
}