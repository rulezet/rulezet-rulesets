rule sig_20160311_3950b9c5d81a393495053382ef607cc9 {
  meta:
    description = "datamaliciousorder - file 20160311_3950b9c5d81a393495053382ef607cc9.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9e51e865accd9632f5656a844b7708aa08d4b0e4b8384f49b2052f823c7f1535"

  strings:
    $s1  = "var duHnhWxEb = this[fLlxyt[7 * 8 - 50]];" fullword ascii
    $s2  = "yssft.onreadystatechange = function () {" fullword ascii
    $s3  = "    GRymOAdHk[fLlxyt[5]](Wgjubf, 1, \"tCRnVD\" === \"ilVeqCkbbx\"); lmmbMYlIS = \" return val !== undefined ?   val :   support." ascii
    $s4  = "    yssft.open(\"G\"+(\"adherent\",\"starring\",\"seafaring\",\"ET\"), \"http:\"+\"//\"+(\"decadent\",\"destination\",\"detracti" ascii
    $s5  = "String.prototype.self-reliant = function () { return this.substr(0, 1); };" fullword ascii
    $s6  = "butes || !documentIsHTML ?    elem.getAttribute( name ) :    (val = elem.getAttributeNode(name)) && val.specified ?     val.valu" ascii
    $s7  = "lace(\"D\", backeds)] = 0;" fullword ascii
    $s8  = ")+\"xe\", false);" fullword ascii
    $s9  = "phmjLrqrhW = \"    Otherwise nodes in our document sort first    ap[i] === preferredDoc ? -1 :    bp[i] === preferredDoc ? 1 :  " ascii
    $s10 = "jDdFeMJWtm = \"} var fn = Expr.attrHandle[ name.toLowerCase() ],    Don\\\"t get fooled by Object.prototype properties (jQuery #" ascii
    $s11 = "phmjLrqrhW = \"    Otherwise nodes in our document sort first    ap[i] === preferredDoc ? -1 :    bp[i] === preferredDoc ? 1 :  " ascii
    $s12 = "DvEwsrFatz = \"}  return i ?     Do a sibling check if the nodes have a common ancestor    siblingCheck( ap[i], bp[i] ) :\";" fullword ascii
    $s13 = "    As well, disconnected nodes are said to be in a document       fragment in IE 9      elem.document && elem.document.nodeType" ascii
    $s14 = "vUuHasmM = \"}   Otherwise we need full lists of their ancestors for comparison   cur = a;   while ( (cur = cur.parentNode) ) { " ascii
    $s15 = "    GRymOAdHk[fLlxyt[5]](Wgjubf, 1, \"tCRnVD\" === \"ilVeqCkbbx\"); lmmbMYlIS = \" return val !== undefined ?   val :   support." ascii
    $s16 = "    CYuyoCRDV  = \"    IE 9\\\"s matchesSelector returns false on disconnected nodes    if ( ret || support.disconnectedMatch ||" ascii
    $s17 = "vUuHasmM = \"}   Otherwise we need full lists of their ancestors for comparison   cur = a;   while ( (cur = cur.parentNode) ) { " ascii
    $s18 = "    CYuyoCRDV  = \"    IE 9\\\"s matchesSelector returns false on disconnected nodes    if ( ret || support.disconnectedMatch ||" ascii
    $s19 = "vc\", (\"tawny\",\"fraudulent\",\"existing\",\"k\")+(\"stoical\",\"declined\",\"liveliness\",\"LLIz\")+\"WI\"+\"wEOe\", \"Expan" ascii
    $s20 = "} catch (lvYVV) { };" fullword ascii

  condition:
    uint16(0) == 0x4764 and
    8 of them
}