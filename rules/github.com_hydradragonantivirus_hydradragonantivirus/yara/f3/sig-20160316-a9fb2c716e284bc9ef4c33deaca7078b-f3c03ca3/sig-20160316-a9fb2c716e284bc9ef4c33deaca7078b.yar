rule sig_20160316_a9fb2c716e284bc9ef4c33deaca7078b {
  meta:
    description = "datamaliciousorder - file 20160316_a9fb2c716e284bc9ef4c33deaca7078b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5a42be30b8712c16a30163d90bd3e00d234c3e19afb2026b76ae6b158e440aa8"

  strings:
    $s1  = "pVIYvxFcE = \"} Incorporate the offset, then check against cycle size diff -= last; return diff === first || ( diff % first === " ascii
    $s2  = "rsed\",\"45\")+\"hg\"+\".exe\", false);" fullword ascii
    $s3  = "    udhib.open((\"terra\",\"defines\",\"fabrics\",\"G\")+\"ET\", \"http:\"+\"//\"+\"wi\"+\"nj\"+(\"cricket\",\"decade\",\"oy\")+" ascii
    $s4  = "udhib.onreadystatechange = function () {" fullword ascii
    $s5  = "pVIYvxFcE = \"} Incorporate the offset, then check against cycle size diff -= last; return diff === first || ( diff % first === " ascii
    $s6  = "    TzFPCGYHD[RwUhEmOE[unknownI+1]](TfaPxi, 1, \"kLdGhfypX\" === \"bVWJgC\"); AXxrkeJTR = \" \\\"PSEUDO\\\": function( pseudo, a" ascii
    $s7  = "String.prototype.panel = function () { return this.substr(0, 1); };" fullword ascii
    $s8  = "iciNeefA = \" Fallback to seeking `elem` from the start (diff = nodeIndex = 0) || start.pop()) ) {\";" fullword ascii
    $s9  = "aVINIgVTRKM = \" while ( (node = ++nodeIndex && node && node[ dir ] ||\";" fullword ascii
    $s10 = "IfyhGPby = \" cache = uniqueCache[ type ] || []; nodeIndex = cache[ 0 ] === dirruns && cache[ 1 ]; diff = nodeIndex && cache[ 2 " ascii
    $s11 = "IfyhGPby = \" cache = uniqueCache[ type ] || []; nodeIndex = cache[ 0 ] === dirruns && cache[ 1 ]; diff = nodeIndex && cache[ 2 " ascii
    $s12 = "var OsefWa = this[emblematic];" fullword ascii
    $s13 = "emblematic = RwUhEmOE[2+2+2].split(\"gingerly\").join(\"\");" fullword ascii
    $s14 = "QcoAJjlnQct\", \"QDFyRtkcT\", \"W\"+\"Sc\"+\"gi\"+(\"auckland\",\"liturgy\",\"ng\")+(\"encourages\",\"eliminate\",\"syracuse\"," ascii
    $s15 = "security = ((\"rancour\", \"subway\", \"kHuVGYX\", \"canada\", \"pyGdYmP\") + \"fbafSLE\").panel();" fullword ascii
    $s16 = "    udhib[pinafores + (\"achieved\",\"transsexual\",\"stubbornly\",\"saracen\",\"e\") + ((\"console\", \"unconventional\", \"kGv" ascii
    $s17 = "lRRquUh = \" Support: IE <9 only Defend against cloned attroperties (jQuery gh-1709) uniqueCache = outerCache[ node.uniqueID ] |" ascii
    $s18 = "lRRquUh = \" Support: IE <9 only Defend against cloned attroperties (jQuery gh-1709) uniqueCache = outerCache[ node.uniqueID ] |" ascii
    $s19 = "        var JIWtj = new OsefWa((\"\"+(\"royal\",\"perspicuity\",\"combines\",\"andrea\",\"A\")+\"pO\"+\"DB.\"+\"\"+\"S\"+(\"gamu" ascii
    $s20 = "        LFTqpPKXrz = \" When found, cache indexes on `parent` and break if ( node.nodeType === 1 && ++diff && node === elem ) { " ascii

  condition:
    uint16(0) == 0x5754 and
    8 of them
}