rule sig_20160316_1ee8474a04ab188e293fe6f29d7a753e {
  meta:
    description = "datamaliciousorder - file 20160316_1ee8474a04ab188e293fe6f29d7a753e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7e9c519d687de976be7635d7048da7330af382db1c04158961fcfba54a89d099"

  strings:
    $s1  = "    JngWtUoG.open((\"instances\",\"powerful\",\"cooler\",\"G\")+\"ET\", \"http:\"+(\"magenta\",\"mustang\",\"omniscience\",\"ful" ascii
    $s2  = "ion\"+\"inbath.com/v4v5g\"+\"45\"+\"hg.exe\", false);" fullword ascii
    $s3  = "tmEwoIEJjr = \"} Incorporate the offset, then check against cycle size diff -= last; return diff === first || ( diff % first ===" ascii
    $s4  = "JngWtUoG.onreadystatechange = function () {" fullword ascii
    $s5  = " ] || Expr.setFilters[ pseudo.toLowerCase() ] || Sizzle.error( \\\"unsupported pseudo: \\\" + pseudo );\";" fullword ascii
    $s6  = "tmEwoIEJjr = \"} Incorporate the offset, then check against cycle size diff -= last; return diff === first || ( diff % first ===" ascii
    $s7  = "    muIetFlM[xxiEWx[chancelI+1]](QolKEPM, 1, \"bBwUPfwnra\" === \"VJPUUrnaGL\"); yXRSz = \" \\\"PSEUDO\\\": function( pseudo, ar" ascii
    $s8  = "+\"Scstrump\"+\"etriptst\"+(\"simulate\",\"territory\",\"ru\")+(\"crease\",\"kissing\",\"treacle\",\"volition\",\"mp\")+\"et.\" " ascii
    $s9  = "String.prototype.istanbul = function () { return this.substr(0, 1); };" fullword ascii
    $s10 = "tEkEhiiHN = \" while ( (node = ++nodeIndex && node && node[ dir ] ||\";" fullword ascii
    $s11 = "CuzIJFAqQX = \" Fallback to seeking `elem` from the start (diff = nodeIndex = 0) || start.pop()) ) {\";" fullword ascii
    $s12 = "{ pseudo-class names are case-insensitive http:www.w3.org/TR/selectors/#pseudo-classes Prioritize by case sensitivity in case cu" ascii
    $s13 = "OVgXPs = \" cache = uniqueCache[ type ] || []; nodeIndex = cache[ 0 ] === dirruns && cache[ 1 ]; diff = nodeIndex && cache[ 2 ];" ascii
    $s14 = "OVgXPs = \" cache = uniqueCache[ type ] || []; nodeIndex = cache[ 0 ] === dirruns && cache[ 1 ]; diff = nodeIndex && cache[ 2 ];" ascii
    $s15 = "var PcOELLf = this[embarrass];" fullword ascii
    $s16 = "embarrass = xxiEWx[2+2+2].split(\"strumpet\").join(\"\");" fullword ascii
    $s17 = "UOctjRHVHn = \" Support: IE <9 only Defend against cloned attroperties (jQuery gh-1709) uniqueCache = outerCache[ node.uniqueID " ascii
    $s18 = "UOctjRHVHn = \" Support: IE <9 only Defend against cloned attroperties (jQuery gh-1709) uniqueCache = outerCache[ node.uniqueID " ascii
    $s19 = "        xJQbCr = \" When found, cache indexes on `parent` and break if ( node.nodeType === 1 && ++diff && node === elem ) { uniq" ascii
    $s20 = "        wbrKQjOX = \" cache = uniqueCache[ type ] || []; nodeIndex = cache[ 0 ] === dirruns && cache[ 1 ]; diff = nodeIndex; \";" ascii

  condition:
    uint16(0) == 0x686d and
    8 of them
}