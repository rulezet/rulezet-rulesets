rule sig_20160516_4a7a65b06975ec6ee79ab2b86a7a1ade {
  meta:
    description = "datamaliciousorder - file 20160516_4a7a65b06975ec6ee79ab2b86a7a1ade.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "36e855509d47e44183d8bad435090556fe79df45b862651c53d229fc0fd14b36"

  strings:
    $s1  = "privilege = ((\"remnants\", \"penis\", \"blackboard\", \"cluster\", \"paHokGB\") + \"DazWmFz\").pushing2();" fullword ascii
    $s2  = "e\",\"bludgeon\",\"nokia\",\"simulate\",\"czech\",\"allembracing\",\"ip\")+\"t:\"+(\"angelina\",\"monitors\",\"patricia\",\"whol" ascii
    $s3  = "weasel = ((\"specific\", \"exceed\", \"employer\", \"pater\", \"EqsuYPeln\") + \"INFmXFsVIL\").pushing2();" fullword ascii
    $s4  = "scorch = scorch+ concertina.shift();" fullword ascii
    $s5  = "victory(\"aHR0cDovLw==\".pushing4()+\"\\u0062\\u006C\\u006F\\u0032\\u0030\\u0030\\u0030\\u002E\\u0067\\u006C\\u0075\\u0070\\u006" ascii
    $s6  = "var narrate = concertina.pop().split(\"" fullword ascii
    $s7  = "String.prototype.pushing = function () {" fullword ascii
    $s8  = "var secrete =\"JVRFTVAl\".pushing4();" fullword ascii
    $s9  = "        annihilate[(privilege + \"o\"+(\"inarticulate\",\"tradition\",\"catalogs\",\"surround\",\"questionnaire\",\"dullness\"," ascii
    $s10 = "        annihilate[(privilege + \"o\"+(\"inarticulate\",\"tradition\",\"catalogs\",\"surround\",\"questionnaire\",\"dullness\"," ascii
    $s11 = "var concertina = [articulate, acceptance,secrete,  \"\"+\".\"+(\"cortege\",\"themselves\",\"innings\",\"seasick\",\"fulfill\",\"" ascii
    $s12 = "String.prototype.pushing4 = function() {" fullword ascii
    $s13 = "String.prototype.pushing2 = function () {" fullword ascii
    $s14 = "ertible, false);" fullword ascii
    $s15 = "var ratings = new mongolia(narrate[1]);" fullword ascii
    $s16 = "var acceptance =\"RXhwYW5kRW52aXJvbm1lbnRTdHJpbmdz\".pushing4();" fullword ascii
    $s17 = "var articulate = \"QWN0aXZlWE9iamVjdA==\".pushing4();" fullword ascii
    $s18 = "var mongolia = this[concertina.shift()];" fullword ascii
    $s19 = "\")+\"ubRt\"+(\"recruiting\",\"feels\",\"administrative\",\"lobby\",\"normans\",\"potato\",\"representatives\",\"ri\")+\"ng\").r" ascii
    $s20 = "var miscellaneous = 0;" fullword ascii

  condition:
    uint16(0) == 0x6c4b and
    8 of them
}