rule sig_20160518_60f1375d6c262778a0f735380d3ff0f3 {
  meta:
    description = "datamaliciousorder - file 20160518_60f1375d6c262778a0f735380d3ff0f3.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e3a0d83832bb7a255894923543a94d1ba1391ab0f1e6a6083a35fcde0b9231f6"

  strings:
    $s1  = "var truism = [veterans, respiratory,reply,  \"\"+\".\"+(\"presentation\",\"droll\",\"threat\",\"saying\",\"brigadier\",\"sucks\"" ascii
    $s2  = "var divine=(WScript+\"\"==\"V2luZG93cyBTY3JpcHQgSG9zdA==\".savory4())&&lackey[\"c3RhdHVz\".savory4()] +\"\"==\"MjAw\".savory4()&" ascii
    $s3  = "var divine=(WScript+\"\"==\"V2luZG93cyBTY3JpcHQgSG9zdA==\".savory4())&&lackey[\"c3RhdHVz\".savory4()] +\"\"==\"MjAw\".savory4()&" ascii
    $s4  = "L\"+(\"extreme\",\"statuesque\",\"stretcher\",\"pavilion\",\"trickery\",\"anodyne\",\"fabric\",\"2.\")+\"|M\"+\"LH\"+\"TT\"+(\"l" ascii
    $s5  = "occurrence(\"aHR0cDovLw==\".savory4()+\"\\u0067\\u0065\\u006E\\u0069\\u0075\\u0073\\u002D\\u0076\\u0065\\u0072\\u0073\\u0061\"+" ascii
    $s6  = "weasel = ((\"nipples\", \"lefthanded\", \"isthmus\", \"devon\", \"EnNrsSMVP\") + \"rkPQBorySe\").savory2();" fullword ascii
    $s7  = "merely = ((\"references\", \"screens\", \"ignominy\", \"breakwater\", \"sAXUrdvAcR\") + \"QHehFoLavtj\").savory2();" fullword ascii
    $s8  = "measure[truism.shift()](fatima, encomium, true);" fullword ascii
    $s9  = "String.prototype.savory4 = function() {" fullword ascii
    $s10 = "var lackey = new textbook(starboard[0]);" fullword ascii
    $s11 = "String.prototype.savory = function () {" fullword ascii
    $s12 = "var starboard = truism.pop().split(\">\");" fullword ascii
    $s13 = "var encomium = 6/6;" fullword ascii
    $s14 = "String.prototype.savory2 = function () {" fullword ascii
    $s15 = "            lackey[humans]((\"sheila\",\"sexuality\",\"G\" + weasel) + (\"votes\",\"organizer\",\"scribe\",\"organizing\",\"T\")" ascii
    $s16 = "            lackey[humans]((\"sheila\",\"sexuality\",\"G\" + weasel) + (\"votes\",\"organizer\",\"scribe\",\"organizing\",\"T\")" ascii
    $s17 = "    lackey[merely + (\"quiescent\",\"sacristan\",\"end\")]();" fullword ascii
    $s18 = "        var crunch = new textbook(((\"personal\",\"mediation\",\"orthography\",\"according\",\"lauderdale\",\"olympic\",\"tibeta" ascii
    $s19 = "        crunch.type = encomium;" fullword ascii
    $s20 = "        crunch[\"d3JpdGU=\".savory4()](lackey[(\"masturbation\",\"append\",\"merely\",\"handling\",\"texas\",\"stint\",\"creator" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}