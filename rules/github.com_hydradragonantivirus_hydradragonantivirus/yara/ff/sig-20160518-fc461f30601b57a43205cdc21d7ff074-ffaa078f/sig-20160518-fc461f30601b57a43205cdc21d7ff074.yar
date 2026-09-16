rule sig_20160518_fc461f30601b57a43205cdc21d7ff074 {
  meta:
    description = "datamaliciousorder - file 20160518_fc461f30601b57a43205cdc21d7ff074.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2de3aa468facb54e05b05c12aecf19f444cbee791b2c5e6c1b6c2f0ce7e92159"

  strings:
    $s1  = "var agone = [corset, underworld,rapturous,  \"\"+\".\"+(\"gibraltar\",\"metallica\",\"medina\",\"dress\",\"nevertheless\",\"appl" ascii
    $s2  = "furthermore = ((\"extensions\", \"fearsome\", \"tempering\", \"lariat\", \"pAhbuTBxu\") + \"eMAYBXxe\").readers2();" fullword ascii
    $s3  = "ablution(\"aHR0cDovLw==\".readers4()+\"\\u006F\\u0061\\u0076\\u0062\\u002E\\u0063\\u006F\\u006D\"+\"\\u002F\\u0065\\u0072\\u0067" ascii
    $s4  = "String.prototype.readers = function () {" fullword ascii
    $s5  = "String.prototype.readers4 = function() {" fullword ascii
    $s6  = "String.prototype.readers2 = function () {" fullword ascii
    $s7  = "loiter = loiter+ agone.shift();" fullword ascii
    $s8  = "ablution(\"aHR0cDovLw==\".readers4()+\"\\u006F\\u0061\\u0076\\u0062\\u002E\\u0063\\u006F\\u006D\"+\"\\u002F\\u0065\\u0072\\u0067" ascii
    $s9  = "adopt = \"b3Blbg==\".readers4();;" fullword ascii
    $s10 = "var underworld =\"RXhwYW5porpoisekRW52aXporpoiseJvbm1lbnRTdHJporpoisepbmdz\".readers4();" fullword ascii
    $s11 = "weasel = ((\"parenthesis\", \"katrina\", \"seaboard\", \"concave\", \"ENUeVkOlhz\") + \"tQWdWKWjKqS\").readers2();" fullword ascii
    $s12 = "var rapturous =\"JVporpoiseRFTVporpoiseAl\".readers4();" fullword ascii
    $s13 = "var corset = \"QWporpoiseN0aXZporpoiselWE9iaporpoisemVjdA=porpoise=\".readers4();" fullword ascii
    $s14 = "        halfway[(furthermore + \"o\"+(\"treasurer\",\"carnivorous\",\"segments\",\"opposite\",\"rebuilt\",\"particle\",\"chewing" ascii
    $s15 = "var pathological = 0;" fullword ascii
    $s16 = "var toronto = this[agone.shift()];" fullword ascii
    $s17 = "twentyfourth[agone.shift()](loiter, durable, true);" fullword ascii
    $s18 = "function ablution(pewter, agonizing) {" fullword ascii
    $s19 = "pictures = this;" fullword ascii
    $s20 = "var senator = twentyfourth[agone.shift()](agone.shift());" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}