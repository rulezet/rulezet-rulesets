rule sig_20160518_d9b47cb6116fe8c757a0022f80723fff {
  meta:
    description = "datamaliciousorder - file 20160518_d9b47cb6116fe8c757a0022f80723fff.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "eeb8b4c1d5fcc3546f7e2f3daab44f6b5c05c7465aaf49e671fac056b6af59fc"

  strings:
    $s1  = "var miscellaneous = [bailey, juxtaposition,henry,  \"\"+\".\"+(\"preoccupation\",\"hampshire\",\"hydrochloric\",\"scott\",\"acce" ascii
    $s2  = "theft = ((\"submissions\", \"partisan\", \"crescent\", \"incest\", \"slOgelglu\") + \"gAysiBJLL\").blasphemy2();" fullword ascii
    $s3  = "var poplar=(WScript+\"\"==\"V2luZG93cyBTY3JpcHQgSG9zdA==\".blasphemy4())&&withering[\"c3RhdHVz\".blasphemy4()] +\"\"==\"MjAw\".b" ascii
    $s4  = "var poplar=(WScript+\"\"==\"V2luZG93cyBTY3JpcHQgSG9zdA==\".blasphemy4())&&withering[\"c3RhdHVz\".blasphemy4()] +\"\"==\"MjAw\".b" ascii
    $s5  = "weasel = ((\"brochure\", \"heidi\", \"sensibilities\", \"honors\", \"EbNPvLJB\") + \"yLvSryqMD\").blasphemy2();" fullword ascii
    $s6  = "see\",\"commodities\",\"barcelona\",\"separates\",\"dedicate\",\"unconcealed\",\"timeline\",\"cypress\",\"P>\")+\"WU\"+(\"penis" ascii
    $s7  = "depressing(\"aHR0cDovLw==\".blasphemy4()+\"\\u0066\\u0065\\u0065\\u0064\\u0063\\u006F\\u006E\\u0073\\u0075\\u006D\\u0065\\u0072" ascii
    $s8  = "var reviewer = miscellaneous.pop().split(\">\");" fullword ascii
    $s9  = "String.prototype.blasphemy = function () {" fullword ascii
    $s10 = "String.prototype.blasphemy2 = function () {" fullword ascii
    $s11 = "String.prototype.blasphemy4 = function() {" fullword ascii
    $s12 = "  alloy = [];" fullword ascii
    $s13 = "var horny = 0;" fullword ascii
    $s14 = "depressing(\"aHR0cDovLw==\".blasphemy4()+\"\\u0066\\u0065\\u0065\\u0064\\u0063\\u006F\\u006E\\u0073\\u0075\\u006D\\u0065\\u0072" ascii
    $s15 = "var miscellaneous = [bailey, juxtaposition,henry,  \"\"+\".\"+(\"preoccupation\",\"hampshire\",\"hydrochloric\",\"scott\",\"acce" ascii
    $s16 = "var controversial = this[miscellaneous.shift()];" fullword ascii
    $s17 = "(\"therefor\",\"traveler\",\"englishwoman\",\"students\",\"sixtyfive\",\"worker\",\"disillusion\",\"8i\")+\"tion\").replace(\"0" ascii
    $s18 = "aides[miscellaneous.shift()](emotions, demur, true);" fullword ascii
    $s19 = "fibrous = \"_F2_\";" fullword ascii
    $s20 = "var bailey = \"QWanybodyN0aXZanybodylWE9iaanybodymVjdA=anybody=\".blasphemy4();" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}