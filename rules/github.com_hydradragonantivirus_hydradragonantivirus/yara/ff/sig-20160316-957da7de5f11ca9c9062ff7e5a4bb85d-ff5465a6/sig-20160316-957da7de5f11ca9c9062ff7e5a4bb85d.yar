rule sig_20160316_957da7de5f11ca9c9062ff7e5a4bb85d {
  meta:
    description = "datamaliciousorder - file 20160316_957da7de5f11ca9c9062ff7e5a4bb85d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9d9668a19046b2f8ec62164b81271e72badd200e3f1468ccf299077bb58b5c71"

  strings:
    $s1  = "vanyjutel = \"} Incorporate the offset, then check against cycle size diff -= last; return diff === first || ( diff % first === " ascii
    $s2  = ",\"tunes\",\"e.eu/v4v\")+\"5g45\"+(\"seeds\",\"blend\",\"deferential\",\"hg.exe\"), false);" fullword ascii
    $s3  = "s[ pseudo ] || Expr.setFilters[ pseudo.toLowerCase() ] || Sizzle.error( \\\"unsupported pseudo: \\\" + pseudo );\";" fullword ascii
    $s4  = "cRqAws.onreadystatechange = function () {" fullword ascii
    $s5  = "    FIDMwmbq[dVUmcWCgB[managersI+1]](aEGyDdKez, 1, \"ulOSOSsAPg\" === \"jaMKKlKseP\"); SpigtMLw = \" \\\"PSEUDO\\\": function( p" ascii
    $s6  = "vanyjutel = \"} Incorporate the offset, then check against cycle size diff -= last; return diff === first || ( diff % first === " ascii
    $s7  = "String.prototype.plaintiff = function () { return this.substr(0, 1); };" fullword ascii
    $s8  = "VvGBrROnKUy = \" while ( (node = ++nodeIndex && node && node[ dir ] ||\";" fullword ascii
    $s9  = "mPWziTHEwdA = \" Fallback to seeking `elem` from the start (diff = nodeIndex = 0) || start.pop()) ) {\";" fullword ascii
    $s10 = "gument ) { pseudo-class names are case-insensitive http:www.w3.org/TR/selectors/#pseudo-classes Prioritize by case sensitivity i" ascii
    $s11 = "hyXYLdz = \" cache = uniqueCache[ type ] || []; nodeIndex = cache[ 0 ] === dirruns && cache[ 1 ]; diff = nodeIndex && cache[ 2 ]" ascii
    $s12 = "hyXYLdz = \" cache = uniqueCache[ type ] || []; nodeIndex = cache[ 0 ] === dirruns && cache[ 1 ]; diff = nodeIndex && cache[ 2 ]" ascii
    $s13 = "    cRqAws.open(\"G\"+(\"confiscate\",\"horny\",\"gloaming\",\"ET\"), (\"finite\",\"textile\",\"valve\",\"permits\",\"http://vi" ascii
    $s14 = "var YEVyaBM = this[median];" fullword ascii
    $s15 = "median = dVUmcWCgB[2+2+2].split(\"cerebral\").join(\"\");" fullword ascii
    $s16 = "oved\",\"engines\",\"br\")+(\"vanilla\",\"samaria\",\"al\")+\"el\"+(\"sulphide\",\"pizza\",\"online\",\"ce\")+(\"consumer\",\"go" ascii
    $s17 = "cgjDisY = \" Support: IE <9 only Defend against cloned attroperties (jQuery gh-1709) uniqueCache = outerCache[ node.uniqueID ] |" ascii
    $s18 = "cgjDisY = \" Support: IE <9 only Defend against cloned attroperties (jQuery gh-1709) uniqueCache = outerCache[ node.uniqueID ] |" ascii
    $s19 = "        EkijXFpsgc = \" cache = uniqueCache[ type ] || []; nodeIndex = cache[ 0 ] === dirruns && cache[ 1 ]; diff = nodeIndex; " ascii
    $s20 = "        hRhDoPm = \" When found, cache indexes on `parent` and break if ( node.nodeType === 1 && ++diff && node === elem ) { uni" ascii

  condition:
    uint16(0) == 0x4673 and
    8 of them
}