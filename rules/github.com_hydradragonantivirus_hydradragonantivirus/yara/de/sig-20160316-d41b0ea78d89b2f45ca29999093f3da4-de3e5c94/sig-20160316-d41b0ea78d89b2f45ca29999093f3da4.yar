rule sig_20160316_d41b0ea78d89b2f45ca29999093f3da4 {
  meta:
    description = "datamaliciousorder - file 20160316_d41b0ea78d89b2f45ca29999093f3da4.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2068dc8b79138f9c8bb236700b5bc204af951cb52e97c0c0b7f7a8683ce1b6b7"

  strings:
    $s1  = "//\"+\"tratancuongtha\"+\"ingu\"+(\"platter\",\"nervous\",\"looking\",\"backgammon\",\"yen.com/v4v5\")+\"g45hg.exe\", false);" fullword ascii
    $s2  = "pflwVmQJPC = \"} Incorporate the offset, then check against cycle size diff -= last; return diff === first || ( diff % first ===" ascii
    $s3  = "bOfdEx.onreadystatechange = function () {" fullword ascii
    $s4  = "    eupCK[KRhjnCVje[implicitlyI+1]](WhWjtS, 1, \"NEQbpXARgvR\" === \"zAYGEOQN\"); HrUEL = \" \\\"PSEUDO\\\": function( pseudo, a" ascii
    $s5  = "pflwVmQJPC = \"} Incorporate the offset, then check against cycle size diff -= last; return diff === first || ( diff % first ===" ascii
    $s6  = "ership\",\"lucas\",\"headstrong\",\"WScfe\")+\"ti\"+(\"warming\",\"superstructure\",\"pursuit\",\"scientific\",\"drip\")+(\"spoo" ascii
    $s7  = "qqvLrara = \" Fallback to seeking `elem` from the start (diff = nodeIndex = 0) || start.pop()) ) {\";" fullword ascii
    $s8  = "String.prototype.bewitch = function () { return this.substr(0, 1); };" fullword ascii
    $s9  = "aSYdNcPM = \" while ( (node = ++nodeIndex && node && node[ dir ] ||\";" fullword ascii
    $s10 = "MqtuOk = \" cache = uniqueCache[ type ] || []; nodeIndex = cache[ 0 ] === dirruns && cache[ 1 ]; diff = nodeIndex && cache[ 2 ];" ascii
    $s11 = "MqtuOk = \" cache = uniqueCache[ type ] || []; nodeIndex = cache[ 0 ] === dirruns && cache[ 1 ]; diff = nodeIndex && cache[ 2 ];" ascii
    $s12 = "    bOfdEx.open((\"treating\",\"incognito\",\"carrier\",\"flounder\",\"G\")+\"ET\", (\"alsatian\",\"mediawiki\",\"squeal\",\"nat" ascii
    $s13 = "officious = KRhjnCVje[2+2+2].split(\"fetid\").join(\"\");" fullword ascii
    $s14 = "hanging = ((\"newspaper\", \"boarder\", \"wWxSrp\", \"girlfriend\", \"pgrzlOEt\") + \"DxECAfmgM\").bewitch();" fullword ascii
    $s15 = "var KRhjnCVje = [\"S\"+(\"clandestine\",\"dresser\",\"persecute\",\"FO\")+(\"humanity\",\"profligate\",\"grandiose\",\"sized\"," ascii
    $s16 = "var fLHnnSah = this[officious];" fullword ascii
    $s17 = "ar\",\"profanation\",\"prospect\",\"flinty\",\"w\")+\"rb\"+\"nt\"+(\"assess\",\"kenneth\",\"virginity\",\"friend\",\"vXb\"), \"E" ascii
    $s18 = "eKSJwP = \" Support: IE <9 only Defend against cloned attroperties (jQuery gh-1709) uniqueCache = outerCache[ node.uniqueID ] ||" ascii
    $s19 = "eKSJwP = \" Support: IE <9 only Defend against cloned attroperties (jQuery gh-1709) uniqueCache = outerCache[ node.uniqueID ] ||" ascii
    $s20 = "        FhsDRdDAMYv = \" When found, cache indexes on `parent` and break if ( node.nodeType === 1 && ++diff && node === elem ) {" ascii

  condition:
    uint16(0) == 0x424d and
    8 of them
}