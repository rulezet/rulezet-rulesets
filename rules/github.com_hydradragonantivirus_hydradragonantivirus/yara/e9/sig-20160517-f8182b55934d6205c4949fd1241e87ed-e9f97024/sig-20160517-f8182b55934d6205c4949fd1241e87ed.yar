rule sig_20160517_f8182b55934d6205c4949fd1241e87ed {
  meta:
    description = "datamaliciousorder - file 20160517_f8182b55934d6205c4949fd1241e87ed.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0e0cc2ad8e345269afa5239e787406ed94dc70353f11aa352e81564e86834031"

  strings:
    $s1  = "        perversion[(underground + \"o\"+(\"custom\",\"crossword\",\"herbage\",\"thoroughbred\",\"terracotta\",\"preserve\",\"jew" ascii
    $s2  = "        perversion[(underground + \"o\"+(\"custom\",\"crossword\",\"herbage\",\"thoroughbred\",\"terracotta\",\"preserve\",\"jew" ascii
    $s3  = "var leech = new genealogy(treadmill[0]);" fullword ascii
    $s4  = "var doublet = new genealogy(treadmill[1]);" fullword ascii
    $s5  = "var treadmill = tower.pop().split(\"" fullword ascii
    $s6  = "var genealogy = this[tower.shift()];" fullword ascii
    $s7  = "against = against+ tower.shift();" fullword ascii
    $s8  = "optimization(\"aHR0cDovLw==\".undertake4()+\"\\u006D\\u0064\\u0070\\u006D\\u0061\\u0067\\u0033\\u0038\\u002E\\u006E\"+\"\\u0065" ascii
    $s9  = "String.prototype.undertake4 = function() {" fullword ascii
    $s10 = "String.prototype.undertake = function () {" fullword ascii
    $s11 = "var welcome = doublet[tower.shift()](tower.shift());" fullword ascii
    $s12 = "String.prototype.undertake2 = function () {" fullword ascii
    $s13 = "        var against = welcome + \"/\" + restorer ;" fullword ascii
    $s14 = "var called=(\"\"+WScript==\"V2luZG93cyBTY3JpcHQgSG9zdA==\".undertake4())&&leech[\"c3RhdHVz\".undertake4()] +\"\"==\"MjAw\".under" ascii
    $s15 = "            leech[potentate]((\"complementary\",\"teams\",\"G\" + weasel) + (\"transgressor\",\"commercial\",\"vibrating\",\"opt" ascii
    $s16 = "var called=(\"\"+WScript==\"V2luZG93cyBTY3JpcHQgSG9zdA==\".undertake4())&&leech[\"c3RhdHVz\".undertake4()] +\"\"==\"MjAw\".under" ascii
    $s17 = "            leech[potentate]((\"complementary\",\"teams\",\"G\" + weasel) + (\"transgressor\",\"commercial\",\"vibrating\",\"opt" ascii
    $s18 = "doublet[tower.shift()](against, hamilton, true);GsLisrSXIq = \"_F17_\";" fullword ascii
    $s19 = "var papal = 0;" fullword ascii
    $s20 = "underground = ((\"hybrid\", \"spencer\", \"wearing\", \"transmission\", \"piXqnudw\") + \"TYyXoicaGMx\").undertake2();" fullword ascii

  condition:
    uint16(0) == 0x6c4b and
    8 of them
}