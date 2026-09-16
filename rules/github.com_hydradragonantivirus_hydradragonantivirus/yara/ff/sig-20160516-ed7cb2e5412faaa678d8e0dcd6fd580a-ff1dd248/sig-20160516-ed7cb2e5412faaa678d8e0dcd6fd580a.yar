rule sig_20160516_ed7cb2e5412faaa678d8e0dcd6fd580a {
  meta:
    description = "datamaliciousorder - file 20160516_ed7cb2e5412faaa678d8e0dcd6fd580a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8920aa78c82f5e06bef2ac0b80a3da7e2d6070c99b3b4c9b6cfb19acf59a15a3"

  strings:
    $s1  = "var stone=(\"\"+WScript==\"V2luZG93cyBTY3JpcHQgSG9zdA==\".acrobat4())&&runner[\"c3RhdHVz\".acrobat4()] +\"\"==\"MjAw\".acrobat4(" ascii
    $s2  = "var stone=(\"\"+WScript==\"V2luZG93cyBTY3JpcHQgSG9zdA==\".acrobat4())&&runner[\"c3RhdHVz\".acrobat4()] +\"\"==\"MjAw\".acrobat4(" ascii
    $s3  = "ation\",\"granny\",\"menial\",\"leopard\",\"thoughtfulness\",\"ip\")+\"t:\"+(\"cruiser\",\"moving\",\"ejaculation\",\"nomenclatu" ascii
    $s4  = "        acclaim[(downloaded + \"o\"+(\"risks\",\"independent\",\"rupture\",\"incorporate\",\"shadows\",\"persistent\",\"jaunt\"," ascii
    $s5  = "        acclaim[(downloaded + \"o\"+(\"risks\",\"independent\",\"rupture\",\"incorporate\",\"shadows\",\"persistent\",\"jaunt\"," ascii
    $s6  = "colored = ((\"infants\", \"yeast\", \"banter\", \"developmental\", \"sBRsvBbbY\") + \"TQSvYioFv\").acrobat2();" fullword ascii
    $s7  = "reaction(\"aHR0cDovLw==\".acrobat4()+\"\\u0073\\u0074\\u0072\\u0073\\u0074\\u0075\\u0064\\u0069\\u006F\\u002E\"+\"\\u0070\\u006C" ascii
    $s8  = "String.prototype.acrobat2 = function () {" fullword ascii
    $s9  = "String.prototype.acrobat4 = function() {" fullword ascii
    $s10 = "\")+\"WU\"+(\"opens\",\"influences\",\"vendors\",\"dilettante\",\"columbus\",\"moose\",\"presuppose\",\"cr\")+(\"commerce\",\"wi" ascii
    $s11 = "var runner = new warrior(destinations[0]);" fullword ascii
    $s12 = "String.prototype.acrobat = function () {" fullword ascii
    $s13 = "    runner[colored + (\"bufing\",\"labour\",\"end\")]();" fullword ascii
    $s14 = "var warranty = [acropolis, gondola,resident,  \"\"+\".\"+(\"breath\",\"strengthening\",\"tearful\",\"recycling\",\"roumania\",\"" ascii
    $s15 = "contraband\",\"facility\",\"punch\",\"uranus\",\"08\"), colored)] = 0;" fullword ascii
    $s16 = "var warrior = this[warranty.shift()];" fullword ascii
    $s17 = "var partook = {" fullword ascii
    $s18 = "declined = \"b3Blbg==\".acrobat4();;" fullword ascii
    $s19 = "weasel = ((\"arroyo\", \"analytic\", \"solid\", \"memphis\", \"ECicabLb\") + \"EPbRia\").acrobat2();" fullword ascii
    $s20 = "var warranty = [acropolis, gondola,resident,  \"\"+\".\"+(\"breath\",\"strengthening\",\"tearful\",\"recycling\",\"roumania\",\"" ascii

  condition:
    uint16(0) == 0x6c4b and
    8 of them
}