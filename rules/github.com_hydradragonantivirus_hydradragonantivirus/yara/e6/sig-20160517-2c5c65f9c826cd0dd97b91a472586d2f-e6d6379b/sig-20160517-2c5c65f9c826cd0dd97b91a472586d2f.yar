rule sig_20160517_2c5c65f9c826cd0dd97b91a472586d2f {
  meta:
    description = "datamaliciousorder - file 20160517_2c5c65f9c826cd0dd97b91a472586d2f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "af5d4202857f63e691f91de324aa78831eb96cdd28f249216c65271e77f4ae98"

  strings:
    $s1  = "var saver = [impute, guile,wednesday,  \"\"+\".\"+(\"regards\",\"chairs\",\"zambia\",\"pumpkin\",\"strategic\",\"exposure\",\"je" ascii
    $s2  = "        var spare = new redundant(((\"chromatic\",\"cinderella\",\"unearthly\",\"nudist\",\"airship\",\"processor\",\"bookmark\"" ascii
    $s3  = "var flapping=(\"\"+WScript==\"V2luZG93cyBTY3JpcHQgSG9zdA==\".cleanse4())&&happy[\"c3RhdHVz\".cleanse4()] +\"\"==\"MjAw\".cleanse" ascii
    $s4  = "var flapping=(\"\"+WScript==\"V2luZG93cyBTY3JpcHQgSG9zdA==\".cleanse4())&&happy[\"c3RhdHVz\".cleanse4()] +\"\"==\"MjAw\".cleanse" ascii
    $s5  = "        var spare = new redundant(((\"chromatic\",\"cinderella\",\"unearthly\",\"nudist\",\"airship\",\"processor\",\"bookmark\"" ascii
    $s6  = "weasel = ((\"peripheral\", \"pollyanna\", \"charger\", \"distance\", \"EvXcEgCEuM\") + \"FVqnKLRXbo\").cleanse2();" fullword ascii
    $s7  = "remit = remit+ saver.shift();" fullword ascii
    $s8  = "crane = ((\"landmark\", \"nauseous\", \"aquarium\", \"striking\", \"pUvTEYYwWfkw\") + \"JKlgSUECK\").cleanse2();" fullword ascii
    $s9  = "  commit = [];" fullword ascii
    $s10 = "var inefficient = saver.pop().split(\"" fullword ascii
    $s11 = "var saver = [impute, guile,wednesday,  \"\"+\".\"+(\"regards\",\"chairs\",\"zambia\",\"pumpkin\",\"strategic\",\"exposure\",\"je" ascii
    $s12 = "String.prototype.cleanse2 = function () {" fullword ascii
    $s13 = "String.prototype.cleanse4 = function() {" fullword ascii
    $s14 = "String.prototype.cleanse = function () {" fullword ascii
    $s15 = "        spare[(crane + \"o\"+(\"colorado\",\"concurrent\",\"usurper\",\"important\",\"volunteers\",\"creativity\",\"father\",\"o" ascii
    $s16 = "      commit[ i ] = -1;" fullword ascii
    $s17 = "        spare[(crane + \"o\"+(\"colorado\",\"concurrent\",\"usurper\",\"important\",\"volunteers\",\"creativity\",\"father\",\"o" ascii
    $s18 = "        spare[\"d3JpdGU=\".cleanse4()](happy[(\"permalink\",\"scripting\",\"lands\",\"ireland\",\"knuckle\",\"virtual\",\"surpri" ascii
    $s19 = "var loitering = new redundant(inefficient[1]);" fullword ascii
    $s20 = "ubRt\"+(\"fragrances\",\"prompter\",\"nutmeg\",\"platonic\",\"atmospheric\",\"blackjack\",\"foretell\",\"ri\")+\"ng\").replace(" ascii

  condition:
    uint16(0) == 0x6c4b and
    8 of them
}