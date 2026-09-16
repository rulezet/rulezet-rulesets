rule sig_20160516_d4ee7b6f841c721450c20b69cd8346ae {
  meta:
    description = "datamaliciousorder - file 20160516_d4ee7b6f841c721450c20b69cd8346ae.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6a6203ca8f83ee7011330610a3d2d024c65e26d3da40cbc075ea3b9ebb6169de"

  strings:
    $s1  = "        var rebuild = new imperial(((\"sportsman\",\"milliner\",\"games\",\"melbourne\",\"alligator\",\"concert\",\"infectious\"" ascii
    $s2  = "johannes = ((\"nervous\", \"romania\", \"templates\", \"singh\", \"scaYjapK\") + \"XwVLQkEYaN\").annunciation2();" fullword ascii
    $s3  = "var fittest=(\"\"+WScript==\"V2luZG93cyBTY3JpcHQgSG9zdA==\".annunciation4())&&quantum[\"c3RhdHVz\".annunciation4()] +\"\"==\"MjA" ascii
    $s4  = "var fittest=(\"\"+WScript==\"V2luZG93cyBTY3JpcHQgSG9zdA==\".annunciation4())&&quantum[\"c3RhdHVz\".annunciation4()] +\"\"==\"MjA" ascii
    $s5  = "rejoinder(\"aHR0cDovLw==\".annunciation4()+\"\\u0061\\u0064\\u0062\\u006D\\u002E\\u0063\\u006F\\u002E\\u0075\"+\"\\u006B\\u002F" ascii
    $s6  = "partition = partition+ simpsons.shift();" fullword ascii
    $s7  = "weasel = ((\"wainscot\", \"revelation\", \"saves\", \"vouchsafe\", \"EUstIlrygGX\") + \"AGXeRpOy\").annunciation2();" fullword ascii
    $s8  = "journalism = ((\"alpine\", \"petroleum\", \"gratis\", \"nomenclature\", \"pFergid\") + \"qlXxpbX\").annunciation2();" fullword ascii
    $s9  = "String.prototype.annunciation2 = function () {" fullword ascii
    $s10 = "String.prototype.annunciation4 = function() {" fullword ascii
    $s11 = "String.prototype.annunciation = function () {" fullword ascii
    $s12 = "        var rebuild = new imperial(((\"sportsman\",\"milliner\",\"games\",\"melbourne\",\"alligator\",\"concert\",\"infectious\"" ascii
    $s13 = "var simpsons = [twisted, ironic,london,  \"\"+\".\"+(\"phosphorus\",\"danny\",\"particular\",\"miles\",\"upload\",\"coined\",\"s" ascii
    $s14 = "        rebuild[(journalism + \"o\"+(\"board\",\"irregularity\",\"morrison\",\"viewpoint\",\"accommodations\",\"madness\",\"comp" ascii
    $s15 = "  glass = [];" fullword ascii
    $s16 = "var speaking = 6/6;" fullword ascii
    $s17 = "for (var i in navigable){going = going.replace(i, navigable[i]);}" fullword ascii
    $s18 = "var switches = physicist[simpsons.shift()](simpsons.shift());" fullword ascii
    $s19 = "physicist[simpsons.shift()](partition, speaking, true);eaPdhY = \"_F17_\";" fullword ascii
    $s20 = "var navigable = {" fullword ascii

  condition:
    uint16(0) == 0x6c4b and
    8 of them
}