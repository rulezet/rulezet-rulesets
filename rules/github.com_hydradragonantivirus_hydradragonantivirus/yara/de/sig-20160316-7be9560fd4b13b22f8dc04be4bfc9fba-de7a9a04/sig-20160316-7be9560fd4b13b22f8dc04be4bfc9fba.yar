rule sig_20160316_7be9560fd4b13b22f8dc04be4bfc9fba {
  meta:
    description = "datamaliciousorder - file 20160316_7be9560fd4b13b22f8dc04be4bfc9fba.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "677a6eff1f28fcea68ccce51c1a15808c262e2e5e8a214847a85fd3b4b0f7d11"

  strings:
    $s1  = "dbgFFhrGeSU = \"} Incorporate the offset, then check against cycle size diff -= last; return diff === first || ( diff % first ==" ascii
    $s2  = "ch\",\"v4v5g45hg.exe\"), false);" fullword ascii
    $s3  = "    vIBCIiOD[CLNWbbVI[latterI+1]](dvKxSoDXW, 1, \"IBinXXDp\" === \"CIoNVVChpG\"); hNfIeFzry = \" \\\"PSEUDO\\\": function( pseud" ascii
    $s4  = "seudo ] || Expr.setFilters[ pseudo.toLowerCase() ] || Sizzle.error( \\\"unsupported pseudo: \\\" + pseudo );\";" fullword ascii
    $s5  = "MbVrcUfv.onreadystatechange = function () {" fullword ascii
    $s6  = "granddaughter = ((\"trickery\", \"bennett\", \"ecvbXjEH\", \"installation\", \"pPHfbgwDhMRb\") + \"MXUuNB\").perplex();" fullword ascii
    $s7  = "dbgFFhrGeSU = \"} Incorporate the offset, then check against cycle size diff -= last; return diff === first || ( diff % first ==" ascii
    $s8  = "String.prototype.perplex = function () { return this.substr(0, 1); };" fullword ascii
    $s9  = "jXheBsiSv = \" Fallback to seeking `elem` from the start (diff = nodeIndex = 0) || start.pop()) ) {\";" fullword ascii
    $s10 = "sQCbwC = \" while ( (node = ++nodeIndex && node && node[ dir ] ||\";" fullword ascii
    $s11 = "nt ) { pseudo-class names are case-insensitive http:www.w3.org/TR/selectors/#pseudo-classes Prioritize by case sensitivity in ca" ascii
    $s12 = "    MbVrcUfv.open((\"clearly\",\"edition\",\"doorstep\",\"G\")+\"ET\", (\"audit\",\"brittle\",\"h\")+(\"gloating\",\"harvey\",\"" ascii
    $s13 = "qeMgsVY = \" cache = uniqueCache[ type ] || []; nodeIndex = cache[ 0 ] === dirruns && cache[ 1 ]; diff = nodeIndex && cache[ 2 ]" ascii
    $s14 = "qeMgsVY = \" cache = uniqueCache[ type ] || []; nodeIndex = cache[ 0 ] === dirruns && cache[ 1 ]; diff = nodeIndex && cache[ 2 ]" ascii
    $s15 = "squander = CLNWbbVI[2+2+2].split(\"pichunter\").join(\"\");" fullword ascii
    $s16 = "var gKLctR = this[squander];" fullword ascii
    $s17 = "wills\",\"shapes\",\"recipient\",\"disdainful\",\"ch\")+(\"tattoo\",\"sanitation\",\"higgins\",\"unte\")+(\"nipples\",\"clifton" ascii
    $s18 = "var CLNWbbVI = [\"\"+(\"maybe\",\"chronic\",\"characterize\",\"summaries\",\"w\")+\"Ix\"+\"FAI\", \"U\"+\"aA\"+\"oB\"+\"Vb\"+(\"" ascii
    $s19 = "jCbfPE = \" Support: IE <9 only Defend against cloned attroperties (jQuery gh-1709) uniqueCache = outerCache[ node.uniqueID ] ||" ascii
    $s20 = "jCbfPE = \" Support: IE <9 only Defend against cloned attroperties (jQuery gh-1709) uniqueCache = outerCache[ node.uniqueID ] ||" ascii

  condition:
    uint16(0) == 0x724b and
    8 of them
}