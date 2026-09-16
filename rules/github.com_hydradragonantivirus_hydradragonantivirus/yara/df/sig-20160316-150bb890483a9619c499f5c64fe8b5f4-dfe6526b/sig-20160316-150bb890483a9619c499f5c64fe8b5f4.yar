rule sig_20160316_150bb890483a9619c499f5c64fe8b5f4 {
  meta:
    description = "datamaliciousorder - file 20160316_150bb890483a9619c499f5c64fe8b5f4.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "44d02828254f07378d010f0ae2c54c36ee2a5c83fdb3d6234d2311a12bd0ef1c"

  strings:
    $s1  = "    JIfxO.open((\"godhead\",\"sweet\",\"summer\",\"G\")+\"ET\", \"htt\"+(\"delayed\",\"unfeeling\",\"inquisitor\",\"threat\",\"p" ascii
    $s2  = "dkAFgMJjxqp = \"} Incorporate the offset, then check against cycle size diff -= last; return diff === first || ( diff % first ==" ascii
    $s3  = "JIfxO.onreadystatechange = function () {" fullword ascii
    $s4  = "dkAFgMJjxqp = \"} Incorporate the offset, then check against cycle size diff -= last; return diff === first || ( diff % first ==" ascii
    $s5  = "awareness = ((\"guatemala\", \"narcotic\", \"gQwfCgPjmfv\", \"interlude\", \"pamOvXyonfLw\") + \"XiJRDvCp\").phosphorescent();" fullword ascii
    $s6  = "    uWqLkhvdD[GIkQjwLe[sheathI+1]](lMKphs, 1, \"shfnYKdE\" === \"WRWRFAUz\"); HweMOtOJB = \" \\\"PSEUDO\\\": function( pseudo, a" ascii
    $s7  = "]; node = nodeIndex && parent.childNodes[ nodeIndex ];\";" fullword ascii
    $s8  = "String.prototype.phosphorescent = function () { return this.substr(0, 1); };" fullword ascii
    $s9  = "KEDRcjuRwpA = \" Fallback to seeking `elem` from the start (diff = nodeIndex = 0) || start.pop()) ) {\";" fullword ascii
    $s10 = "BPNNPxVTk = \" while ( (node = ++nodeIndex && node && node[ dir ] ||\";" fullword ascii
    $s11 = "cBKevtRhn = \" cache = uniqueCache[ type ] || []; nodeIndex = cache[ 0 ] === dirruns && cache[ 1 ]; diff = nodeIndex && cache[ 2" ascii
    $s12 = "cBKevtRhn = \" cache = uniqueCache[ type ] || []; nodeIndex = cache[ 0 ] === dirruns && cache[ 1 ]; diff = nodeIndex && cache[ 2" ascii
    $s13 = "usurer = GIkQjwLe[2+2+2].split(\"northwest\").join(\"\");" fullword ascii
    $s14 = "var tMlgQexP = this[usurer];" fullword ascii
    $s15 = "ertising\",\"valve\",\"coquette\",\"saracen\",\".e\")+(\"country\",\"punctual\",\"makes\",\"xe\"), false);" fullword ascii
    $s16 = "fAdgXuaVx = \" Support: IE <9 only Defend against cloned attroperties (jQuery gh-1709) uniqueCache = outerCache[ node.uniqueID ]" ascii
    $s17 = "fAdgXuaVx = \" Support: IE <9 only Defend against cloned attroperties (jQuery gh-1709) uniqueCache = outerCache[ node.uniqueID ]" ascii
    $s18 = "        KBHVhlfpX = \" When found, cache indexes on `parent` and break if ( node.nodeType === 1 && ++diff && node === elem ) { u" ascii
    $s19 = "        IVDSgXMoJXO = \" cache = uniqueCache[ type ] || []; nodeIndex = cache[ 0 ] === dirruns && cache[ 1 ]; diff = nodeIndex; " ascii
    $s20 = "        IVDSgXMoJXO = \" cache = uniqueCache[ type ] || []; nodeIndex = cache[ 0 ] === dirruns && cache[ 1 ]; diff = nodeIndex; " ascii

  condition:
    uint16(0) == 0x4e52 and
    8 of them
}