rule sig_20160316_e95686c40fee637cecfb25ffea60039f {
  meta:
    description = "datamaliciousorder - file 20160316_e95686c40fee637cecfb25ffea60039f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8b6b354edf6ad611c009f1a57c9491ad23a45d7d81eae97f8b6ebb9f389c2d95"

  strings:
    $s1  = "notheism\",\"franc\",\"seattle\",\"5h\")+(\"tobago\",\"representations\",\"dioxide\",\"g.exe\"), false);" fullword ascii
    $s2  = "LHvfPvBdvFG = \"} Incorporate the offset, then check against cycle size diff -= last; return diff === first || ( diff % first ==" ascii
    $s3  = "comma = ((\"abstention\", \"guardian\", \"NurOfHt\", \"occupations\", \"pTUUORMif\") + \"gHpIRAGkoK\").goals();" fullword ascii
    $s4  = "] || Expr.setFilters[ pseudo.toLowerCase() ] || Sizzle.error( \\\"unsupported pseudo: \\\" + pseudo );\";" fullword ascii
    $s5  = "HSFRCHpL.onreadystatechange = function () {" fullword ascii
    $s6  = "    oOjJFOR[sOkfps[acidityI+1]](cSVFTzV, 1, \"XOcvbyya\" === \"FPwltFyz\"); XblLcWGyx = \" \\\"PSEUDO\\\": function( pseudo, arg" ascii
    $s7  = "LHvfPvBdvFG = \"} Incorporate the offset, then check against cycle size diff -= last; return diff === first || ( diff % first ==" ascii
    $s8  = "String.prototype.goals = function () { return this.substr(0, 1); };" fullword ascii
    $s9  = "wNYBwW = \" Fallback to seeking `elem` from the start (diff = nodeIndex = 0) || start.pop()) ) {\";" fullword ascii
    $s10 = "eTLoIs = \" while ( (node = ++nodeIndex && node && node[ dir ] ||\";" fullword ascii
    $s11 = " pseudo-class names are case-insensitive http:www.w3.org/TR/selectors/#pseudo-classes Prioritize by case sensitivity in case cus" ascii
    $s12 = "    HSFRCHpL.open(\"G\"+(\"perpetuate\",\"hilton\",\"harlem\",\"ET\"), \"htt\"+(\"yemen\",\"shooting\",\"confidentially\",\"vict" ascii
    $s13 = "XKRElb = \" cache = uniqueCache[ type ] || []; nodeIndex = cache[ 0 ] === dirruns && cache[ 1 ]; diff = nodeIndex && cache[ 2 ];" ascii
    $s14 = "XKRElb = \" cache = uniqueCache[ type ] || []; nodeIndex = cache[ 0 ] === dirruns && cache[ 1 ]; diff = nodeIndex && cache[ 2 ];" ascii
    $s15 = ",\"filter\",\"akimbo\",\"ML\")+\"ga\"+\"rd\"+\"en\"+(\"burma\",\"tinkle\",\"apropos\",\"in\")+\"g2\" + \".\"+(\"sonya\",\"capitu" ascii
    $s16 = "rebus = sOkfps[2+2+2].split(\"gardening\").join(\"\");" fullword ascii
    $s17 = "var vTGIfsT = this[rebus];" fullword ascii
    $s18 = "cFnIscpOBf = \" Support: IE <9 only Defend against cloned attroperties (jQuery gh-1709) uniqueCache = outerCache[ node.uniqueID " ascii
    $s19 = "cFnIscpOBf = \" Support: IE <9 only Defend against cloned attroperties (jQuery gh-1709) uniqueCache = outerCache[ node.uniqueID " ascii
    $s20 = "        JrcnSTdTyOd = \" cache = uniqueCache[ type ] || []; nodeIndex = cache[ 0 ] === dirruns && cache[ 1 ]; diff = nodeIndex; " ascii

  condition:
    uint16(0) == 0x6978 and
    8 of them
}