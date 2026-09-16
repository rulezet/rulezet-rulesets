rule sig_20160518_88d47453458724de85351965bac8a18b {
  meta:
    description = "datamaliciousorder - file 20160518_88d47453458724de85351965bac8a18b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0766b4714d9883a7cc1c4d5bf10845b4c68f23d0c3162780bb6dc8b1b625cfea"

  strings:
    $s1  = "        happened[(reducing + \"o\"+(\"lions\",\"perplex\",\"fiber\",\"ninetytwo\",\"outsourcing\",\"emmanuel\",\"perth\",\"idiom" ascii
    $s2  = "var uncertainty = [resounding, shaped,mutation,  \"\"+\".\"+(\"naked\",\"mahdi\",\"battleship\",\"guinea\",\"dependency\",\"trui" ascii
    $s3  = "var experiencing=(WScript+\"\"==\"V2luZG93cyBTY3JpcHQgSG9zdA==\".taffrail4())&&florence[\"c3RhdHVz\".taffrail4()] +\"\"==\"MjAw" ascii
    $s4  = "var experiencing=(WScript+\"\"==\"V2luZG93cyBTY3JpcHQgSG9zdA==\".taffrail4())&&florence[\"c3RhdHVz\".taffrail4()] +\"\"==\"MjAw" ascii
    $s5  = "terrain = terrain+ uncertainty.shift();" fullword ascii
    $s6  = "weasel = ((\"bosnia\", \"digits\", \"crammed\", \"admission\", \"EaIjMkdzF\") + \"fjjFUXOPNV\").taffrail2();" fullword ascii
    $s7  = "emission(\"aHR0cDovLw==\".taffrail4()+\"\\u006F\\u006C\\u0067\\u0061\\u0073\\u0074\\u0075\\u0064\\u0069\\u006F\"+\"\\u002E\\u007" ascii
    $s8  = "reducing = ((\"tackle\", \"smoking\", \"makeup\", \"lesbians\", \"pTCYdJs\") + \"Lgchcx\").taffrail2();" fullword ascii
    $s9  = "snatching = ((\"oxide\", \"pagoda\", \"mixer\", \"solidity\", \"sPQrQQN\") + \"JyyxamT\").taffrail2();" fullword ascii
    $s10 = "var chronological = uncertainty.pop().split(\">\");" fullword ascii
    $s11 = "String.prototype.taffrail = function () {" fullword ascii
    $s12 = "String.prototype.taffrail4 = function() {" fullword ascii
    $s13 = "String.prototype.taffrail2 = function () {" fullword ascii
    $s14 = "var florence = new anatomical(chronological[0]);" fullword ascii
    $s15 = "var should = new anatomical(chronological[1]);" fullword ascii
    $s16 = "var unknown = should[uncertainty.shift()](uncertainty.shift());" fullword ascii
    $s17 = "var mutation =\"JVmioceneRFTVmioceneAl\".taffrail4();" fullword ascii
    $s18 = "adrift = \"b3Blbg==\".taffrail4();;" fullword ascii
    $s19 = "var uncertainty = [resounding, shaped,mutation,  \"\"+\".\"+(\"naked\",\"mahdi\",\"battleship\",\"guinea\",\"dependency\",\"trui" ascii
    $s20 = "should[uncertainty.shift()](terrain, attraction, true);" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}