rule sig_20160316_aa111fb939f9585232134dac5393307c {
  meta:
    description = "datamaliciousorder - file 20160316_aa111fb939f9585232134dac5393307c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "89b2516c24dc430da4119eeae44f417c2c94965b964e7ad762e8f109d29f9967"

  strings:
    $s1  = "HVnaxYrvM = \"} Incorporate the offset, then check against cycle size diff -= last; return diff === first || ( diff % first === " ascii
    $s2  = "| Expr.setFilters[ pseudo.toLowerCase() ] || Sizzle.error( \\\"unsupported pseudo: \\\" + pseudo );\";" fullword ascii
    $s3  = "wuvBvGgYQ.onreadystatechange = function () {" fullword ascii
    $s4  = "    xHRkJdm[baKlS[conradI+1]](XeKlWivI, 1, \"SXgMibvsRGq\" === \"jWvgXwm\"); WuVGH = \" \\\"PSEUDO\\\": function( pseudo, argume" ascii
    $s5  = "HVnaxYrvM = \"} Incorporate the offset, then check against cycle size diff -= last; return diff === first || ( diff % first === " ascii
    $s6  = "idpNrJySMd = \" while ( (node = ++nodeIndex && node && node[ dir ] ||\";" fullword ascii
    $s7  = "pJKrCJ = \" Fallback to seeking `elem` from the start (diff = nodeIndex = 0) || start.pop()) ) {\";" fullword ascii
    $s8  = "String.prototype.optimum = function () { return this.substr(0, 1); };" fullword ascii
    $s9  = "eudo-class names are case-insensitive http:www.w3.org/TR/selectors/#pseudo-classes Prioritize by case sensitivity in case custom" ascii
    $s10 = "NeDivXmkul = \" cache = uniqueCache[ type ] || []; nodeIndex = cache[ 0 ] === dirruns && cache[ 1 ]; diff = nodeIndex && cache[ " ascii
    $s11 = "NeDivXmkul = \" cache = uniqueCache[ type ] || []; nodeIndex = cache[ 0 ] === dirruns && cache[ 1 ]; diff = nodeIndex && cache[ " ascii
    $s12 = "masturbation = baKlS[2+2+2].split(\"gamma\").join(\"\");" fullword ascii
    $s13 = "var EFmsce = this[masturbation];" fullword ascii
    $s14 = "eputable\",\"nj\")+\"oy\"+\"tech\"+\"no\"+\"lo\"+\"gi\"+\"es\"+\".c\"+\"om\"+\"/v\"+\"4v\"+\"5g\"+\"45\"+\"hg\"+\".e\"+\"xe\", f" ascii
    $s15 = "JlrTBkUqWkU = \" Support: IE <9 only Defend against cloned attroperties (jQuery gh-1709) uniqueCache = outerCache[ node.uniqueID" ascii
    $s16 = "JlrTBkUqWkU = \" Support: IE <9 only Defend against cloned attroperties (jQuery gh-1709) uniqueCache = outerCache[ node.uniqueID" ascii
    $s17 = "        yzSquegkT = \" Support: IE <9 only Defend against cloned attroperties (jQuery gh-1709) uniqueCache = outerCache[ node.un" ascii
    $s18 = "        UrhGKFKKH = \" cache = uniqueCache[ type ] || []; nodeIndex = cache[ 0 ] === dirruns && cache[ 1 ]; diff = nodeIndex; \"" ascii
    $s19 = "        LiQBXVayu = \" When found, cache indexes on `parent` and break if ( node.nodeType === 1 && ++diff && node === elem ) { u" ascii
    $s20 = "    wuvBvGgYQ.open(\"G\"+(\"referral\",\"salty\",\"signet\",\"ET\"), \"h\"+\"tt\"+\"p:\"+(\"cayman\",\"mario\",\"//\")+\"wi\"+(" ascii

  condition:
    uint16(0) == 0x5042 and
    8 of them
}