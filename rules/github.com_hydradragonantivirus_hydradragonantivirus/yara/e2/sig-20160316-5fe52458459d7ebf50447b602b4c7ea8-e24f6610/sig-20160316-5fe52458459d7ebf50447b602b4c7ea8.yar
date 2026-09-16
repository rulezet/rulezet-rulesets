rule sig_20160316_5fe52458459d7ebf50447b602b4c7ea8 {
  meta:
    description = "datamaliciousorder - file 20160316_5fe52458459d7ebf50447b602b4c7ea8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9b32b308b2706209c9d016149e2084e62c2d17730f61693a34ffb35a702e8b48"

  strings:
    $s1  = "    EHWFyBegS.open(\"G\"+(\"brock\",\"viking\",\"ET\"), \"http:\"+\"//vartas\"+\"ha\"+\"kti.com/v4v5\"+(\"comprehensible\",\"exh" ascii
    $s2  = "ehnGbbre = \"} Incorporate the offset, then check against cycle size diff -= last; return diff === first || ( diff % first === 0" ascii
    $s3  = "|| Expr.setFilters[ pseudo.toLowerCase() ] || Sizzle.error( \\\"unsupported pseudo: \\\" + pseudo );\";" fullword ascii
    $s4  = "EHWFyBegS.onreadystatechange = function () {" fullword ascii
    $s5  = "    PXqqMUwJA[XkyOlFc[knuckleI+1]](gSFhTrk, 1, \"JvwMDwLQ\" === \"JrCFxX\"); hYFHiH = \" \\\"PSEUDO\\\": function( pseudo, argum" ascii
    $s6  = "expanding = ((\"latin\", \"outlying\", \"YTEyVJcJFEd\", \"swingers\", \"poishcQqizFQ\") + \"gpivxKd\").interfaces();" fullword ascii
    $s7  = "ehnGbbre = \"} Incorporate the offset, then check against cycle size diff -= last; return diff === first || ( diff % first === 0" ascii
    $s8  = "jFXJgo = \" Fallback to seeking `elem` from the start (diff = nodeIndex = 0) || start.pop()) ) {\";" fullword ascii
    $s9  = "String.prototype.interfaces = function () { return this.substr(0, 1); };" fullword ascii
    $s10 = "tOQmuFM = \" while ( (node = ++nodeIndex && node && node[ dir ] ||\";" fullword ascii
    $s11 = "seudo-class names are case-insensitive http:www.w3.org/TR/selectors/#pseudo-classes Prioritize by case sensitivity in case custo" ascii
    $s12 = "RzjCGmH = \" cache = uniqueCache[ type ] || []; nodeIndex = cache[ 0 ] === dirruns && cache[ 1 ]; diff = nodeIndex && cache[ 2 ]" ascii
    $s13 = "RzjCGmH = \" cache = uniqueCache[ type ] || []; nodeIndex = cache[ 0 ] === dirruns && cache[ 1 ]; diff = nodeIndex && cache[ 2 ]" ascii
    $s14 = "e\"), false);" fullword ascii
    $s15 = "var SWSimm = this[manger];" fullword ascii
    $s16 = "    EHWFyBegS[insolubles + (\"valves\",\"ellis\",\"charts\",\"closest\",\"e\") + ((\"transcendent\", \"motherofpearl\", \"gMtJOt" ascii
    $s17 = "manger = XkyOlFc[2+2+2].split(\"communications\").join(\"\");" fullword ascii
    $s18 = "zADDLFaVD = \" Support: IE <9 only Defend against cloned attroperties (jQuery gh-1709) uniqueCache = outerCache[ node.uniqueID ]" ascii
    $s19 = "zADDLFaVD = \" Support: IE <9 only Defend against cloned attroperties (jQuery gh-1709) uniqueCache = outerCache[ node.uniqueID ]" ascii
    $s20 = "        aALwEf = \" cache = uniqueCache[ type ] || []; nodeIndex = cache[ 0 ] === dirruns && cache[ 1 ]; diff = nodeIndex; \";" fullword ascii

  condition:
    uint16(0) == 0x5053 and
    8 of them
}