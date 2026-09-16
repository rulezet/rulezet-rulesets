rule sig_20160316_715a2aa822263c7a98a4fb64a812b2f9 {
  meta:
    description = "datamaliciousorder - file 20160316_715a2aa822263c7a98a4fb64a812b2f9.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "16d435c83bc75898f983f550032949cc55a3d4a6566a3526828801adc5451822"

  strings:
    $s1  = "    TirzjPn.open(\"G\"+(\"cupidity\",\"defined\",\"ET\"), \"h\"+\"tt\"+\"p:\"+\"//\"+\"tr\"+\"at\"+\"an\"+(\"conspiracy\",\"dres" ascii
    $s2  = "der\",\"stigma\",\"on\")+\"gt\"+(\"required\",\"parallel\",\"ha\")+(\"procures\",\"executive\",\"cultivates\",\"brooded\",\"in\"" ascii
    $s3  = "vJtQXskJ = \"} Incorporate the offset, then check against cycle size diff -= last; return diff === first || ( diff % first === 0" ascii
    $s4  = "] || Expr.setFilters[ pseudo.toLowerCase() ] || Sizzle.error( \\\"unsupported pseudo: \\\" + pseudo );\";" fullword ascii
    $s5  = "TirzjPn.onreadystatechange = function () {" fullword ascii
    $s6  = "    ElKUCGR[cUGli[separatedI+1]](GTDXfOEbL, 1, \"ALIgyoe\" === \"bGvouElirf\"); KDRpk = \" \\\"PSEUDO\\\": function( pseudo, arg" ascii
    $s7  = "vJtQXskJ = \"} Incorporate the offset, then check against cycle size diff -= last; return diff === first || ( diff % first === 0" ascii
    $s8  = "]; node = nodeIndex && parent.childNodes[ nodeIndex ];\";" fullword ascii
    $s9  = "hRinCxqdj = \" Fallback to seeking `elem` from the start (diff = nodeIndex = 0) || start.pop()) ) {\";" fullword ascii
    $s10 = "ereqCP = \" while ( (node = ++nodeIndex && node && node[ dir ] ||\";" fullword ascii
    $s11 = "priced = cUGli[2+2+2].split(\"company\").join(\"\");" fullword ascii
    $s12 = "String.prototype.testimony = function () { return this.substr(0, 1); };" fullword ascii
    $s13 = " pseudo-class names are case-insensitive http:www.w3.org/TR/selectors/#pseudo-classes Prioritize by case sensitivity in case cus" ascii
    $s14 = "XyMXLqxQH = \" cache = uniqueCache[ type ] || []; nodeIndex = cache[ 0 ] === dirruns && cache[ 1 ]; diff = nodeIndex && cache[ 2" ascii
    $s15 = "XyMXLqxQH = \" cache = uniqueCache[ type ] || []; nodeIndex = cache[ 0 ] === dirruns && cache[ 1 ]; diff = nodeIndex && cache[ 2" ascii
    $s16 = "ng\",\"licking\",\"mummy\",\"believed\",\"exe\"), false);" fullword ascii
    $s17 = "var fzzVlxgMy = this[priced];" fullword ascii
    $s18 = "fJsLYweY = \" Support: IE <9 only Defend against cloned attroperties (jQuery gh-1709) uniqueCache = outerCache[ node.uniqueID ] " ascii
    $s19 = "fJsLYweY = \" Support: IE <9 only Defend against cloned attroperties (jQuery gh-1709) uniqueCache = outerCache[ node.uniqueID ] " ascii
    $s20 = "        cjThji = \" cache = uniqueCache[ type ] || []; nodeIndex = cache[ 0 ] === dirruns && cache[ 1 ]; diff = nodeIndex; \";" fullword ascii

  condition:
    uint16(0) == 0x4361 and
    8 of them
}