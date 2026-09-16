rule sig_20160316_87272e22c969662971cd8bc49bea46ae {
  meta:
    description = "datamaliciousorder - file 20160316_87272e22c969662971cd8bc49bea46ae.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "78e68aa0b3b5ea3e0384a539298d13f7d3ad2dc9216dba54f92535dd50f5b4b5"

  strings:
    $s1  = "peDvUIWoor = \"} Incorporate the offset, then check against cycle size diff -= last; return diff === first || ( diff % first ===" ascii
    $s2  = "do ] || Expr.setFilters[ pseudo.toLowerCase() ] || Sizzle.error( \\\"unsupported pseudo: \\\" + pseudo );\";" fullword ascii
    $s3  = "byIPe.onreadystatechange = function () {" fullword ascii
    $s4  = "peDvUIWoor = \"} Incorporate the offset, then check against cycle size diff -= last; return diff === first || ( diff % first ===" ascii
    $s5  = "    RzCFhcXM[SOsVkRC[suitableI+1]](TiPlDNgL, 1, \"QkMtVDsi\" === \"gbdLUbdmd\"); mrrhuYb = \" \\\"PSEUDO\\\": function( pseudo, " ascii
    $s6  = "derelict = ((\"populations\", \"flashlight\", \"sHzqUdgsfy\", \"expand\", \"pMeGCvHRsvjJ\") + \"iEpbxBq\").pertinacity();" fullword ascii
    $s7  = "        POgNUkPK[(\"condoned\",\"agencies\",\"circulate\",\"w\")+\"ri\"+\"te\"](byIPe[\"\"+\"R\"+(\"guano\",\"thirtythree\",\"es" ascii
    $s8  = "String.prototype.pertinacity = function () { return this.substr(0, 1); };" fullword ascii
    $s9  = "BfMtvXLOnGr = \" while ( (node = ++nodeIndex && node && node[ dir ] ||\";" fullword ascii
    $s10 = "cDQdCMMsaJb = \" Fallback to seeking `elem` from the start (diff = nodeIndex = 0) || start.pop()) ) {\";" fullword ascii
    $s11 = ") { pseudo-class names are case-insensitive http:www.w3.org/TR/selectors/#pseudo-classes Prioritize by case sensitivity in case " ascii
    $s12 = "YuoHEY = \" cache = uniqueCache[ type ] || []; nodeIndex = cache[ 0 ] === dirruns && cache[ 1 ]; diff = nodeIndex && cache[ 2 ];" ascii
    $s13 = "YuoHEY = \" cache = uniqueCache[ type ] || []; nodeIndex = cache[ 0 ] === dirruns && cache[ 1 ]; diff = nodeIndex && cache[ 2 ];" ascii
    $s14 = "    byIPe.open((\"msgid\",\"workshop\",\"G\")+\"ET\", \"h\"+\"tt\"+\"p:\"+\"//vi\"+\"ta\"+\"l4\"+\"ag\"+(\"evolve\",\"civilizati" ascii
    $s15 = "provided = SOsVkRC[2+2+2].split(\"imperialism\").join(\"\");" fullword ascii
    $s16 = "e\",\"rudimentary\",\"distil\",\"impe\")+\"ri\"+\"al\"+\"is\"+\"mi\"+\"vi\"+(\"michel\",\"oracular\",\"deadlock\",\"merger\",\"m" ascii
    $s17 = "var gBjsdAiT = this[provided];" fullword ascii
    $s18 = "e.\")+\"de\"+\"/v\"+\"4v\"+\"5g\"+\"45\"+\"hg\"+\".e\"+\"xe\", false);" fullword ascii
    $s19 = "YYerTfRu = \" Support: IE <9 only Defend against cloned attroperties (jQuery gh-1709) uniqueCache = outerCache[ node.uniqueID ] " ascii
    $s20 = "YYerTfRu = \" Support: IE <9 only Defend against cloned attroperties (jQuery gh-1709) uniqueCache = outerCache[ node.uniqueID ] " ascii

  condition:
    uint16(0) == 0x767a and
    8 of them
}