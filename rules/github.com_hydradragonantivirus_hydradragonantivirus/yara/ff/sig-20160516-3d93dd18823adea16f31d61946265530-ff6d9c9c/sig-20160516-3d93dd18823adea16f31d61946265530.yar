rule sig_20160516_3d93dd18823adea16f31d61946265530 {
  meta:
    description = "datamaliciousorder - file 20160516_3d93dd18823adea16f31d61946265530.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3069e50f87f33c45e53f730807cbe4a542a60d205f850558fcb0d24d6c26d810"

  strings:
    $s1  = "portrait = portrait+ collation.shift();" fullword ascii
    $s2  = "weasel = ((\"halves\", \"polyester\", \"truncheon\", \"mulatto\", \"ErNVSaCDC\") + \"IsMhjfb\").enhancement2();" fullword ascii
    $s3  = "var shipping=(\"\"+WScript==\"V2luZG93cyBTY3JpcHQgSG9zdA==\".enhancement4())&&undefiled[\"c3RhdHVz\".enhancement4()] +\"\"==\"Mj" ascii
    $s4  = "var shipping=(\"\"+WScript==\"V2luZG93cyBTY3JpcHQgSG9zdA==\".enhancement4())&&undefiled[\"c3RhdHVz\".enhancement4()] +\"\"==\"Mj" ascii
    $s5  = "            undefiled[corresponds]((\"thwart\",\"invite\",\"G\" + weasel) + (\"utilization\",\"awkwardly\",\"architecture\",\"ac" ascii
    $s6  = "        drawbridge[(exclusively + \"o\"+(\"scorch\",\"adams\",\"publishing\",\"fulsome\",\"registration\",\"protestation\",\"tur" ascii
    $s7  = "exclusively = ((\"mirrors\", \"midlands\", \"environmental\", \"deprivation\", \"pgDmfrTq\") + \"MLgvRBA\").enhancement2();" fullword ascii
    $s8  = "corporate(\"aHR0cDovLw==\".enhancement4()+\"\\u006D\\u0072\\u0032\\u0070\\u0065\\u0074\\u0065\\u0072\\u002E\\u0064\"+\"\\u0065" ascii
    $s9  = "String.prototype.enhancement4 = function() {" fullword ascii
    $s10 = "String.prototype.enhancement2 = function () {" fullword ascii
    $s11 = "investment[collation.shift()](portrait, solvent, true);pknDvrGC = \"_F17_\";" fullword ascii
    $s12 = "\"), newcomer, false);" fullword ascii
    $s13 = "String.prototype.enhancement = function () {" fullword ascii
    $s14 = "function corporate(newcomer, succinct) {" fullword ascii
    $s15 = "            undefiled[corresponds]((\"thwart\",\"invite\",\"G\" + weasel) + (\"utilization\",\"awkwardly\",\"architecture\",\"ac" ascii
    $s16 = "var collation = [steering, worth,sensuality,  \"\"+\".\"+(\"bystander\",\"definition\",\"genius\",\"chute\",\"aroma\",\"mischanc" ascii
    $s17 = "        drawbridge[(\"incognito\",\"lucia\",\"icons\",\"closer\",\"rectum\",\"headline\",\"usurped\",\"w\")+\"ri\"+\"te\"](undef" ascii
    $s18 = "        var portrait = tudor + \"/\" + succinct ;" fullword ascii
    $s19 = "        var drawbridge = new directors(((\"determined\",\"gluttony\",\"compare\",\"prematurely\",\"elucidate\",\"residuum\",\"re" ascii
    $s20 = "var directors = this[collation.shift()];" fullword ascii

  condition:
    uint16(0) == 0x6c4b and
    8 of them
}