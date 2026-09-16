rule sig_20160518_4aef3830f13655e2449325b8ef36ad76 {
  meta:
    description = "datamaliciousorder - file 20160518_4aef3830f13655e2449325b8ef36ad76.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c9bf7f0cbedf623599356083f50a59db530643928dd100d08f55629b4a778d7b"

  strings:
    $s1  = "        coverage[(gloucestershire + \"o\"+(\"anxiety\",\"barbados\",\"flurry\",\"polls\",\"wallet\",\"oversight\",\"forthcoming" ascii
    $s2  = "var adept=(WScript+\"\"==\"V2luZG93cyBTY3JpcHQgSG9zdA==\".respiratory4())&&tardily[\"c3RhdHVz\".respiratory4()] +\"\"==\"MjAw\"." ascii
    $s3  = "var adept=(WScript+\"\"==\"V2luZG93cyBTY3JpcHQgSG9zdA==\".respiratory4())&&tardily[\"c3RhdHVz\".respiratory4()] +\"\"==\"MjAw\"." ascii
    $s4  = "var louse = [panorama, deafness,accelerated,  \"\"+\".\"+(\"intermittently\",\"festival\",\"porsche\",\"clinic\",\"kenny\",\"oxf" ascii
    $s5  = "        var coverage = new votes(((\"productivity\",\"anxiety\",\"midway\",\"bryan\",\"beholden\",\"right\",\"dialog\",\"capstan" ascii
    $s6  = "chord = chord+ louse.shift();" fullword ascii
    $s7  = "aurora(\"aHR0cDovLw==\".respiratory4()+\"\\u0077\\u0077\\u0077\\u002E\\u0062\\u0061\\u0072\\u0074\\u0068\\u002D\\u0073\\u0061\\u" ascii
    $s8  = "function aurora(computational, moira) {" fullword ascii
    $s9  = "String.prototype.respiratory4 = function() {" fullword ascii
    $s10 = "String.prototype.respiratory2 = function () {" fullword ascii
    $s11 = "String.prototype.respiratory = function () {" fullword ascii
    $s12 = "            tardily[themes]((\"crumbled\",\"senior\",\"G\" + weasel) + (\"clamor\",\"colossus\",\"auntie\",\"nectar\",\"T\"), co" ascii
    $s13 = "            tardily[themes]((\"crumbled\",\"senior\",\"G\" + weasel) + (\"clamor\",\"colossus\",\"auntie\",\"nectar\",\"T\"), co" ascii
    $s14 = "        coverage[(gloucestershire + \"o\"+(\"anxiety\",\"barbados\",\"flurry\",\"polls\",\"wallet\",\"oversight\",\"forthcoming" ascii
    $s15 = "var bugbear = 6/6;" fullword ascii
    $s16 = "var votes = this[louse.shift()];" fullword ascii
    $s17 = "var panorama = \"QWparlanceN0aXZparlancelWE9iaparlancemVjdA=parlance=\".respiratory4();" fullword ascii
    $s18 = "var purify = {" fullword ascii
    $s19 = "\"+(\"essex\",\"shingles\",\"timing\",\"viands\",\"tulip\",\"analyse\",\"upset\",\"2.\")+\"|M\"+\"LH\"+\"TT\"+(\"before\",\"goth" ascii
    $s20 = "weasel = ((\"metaphorical\", \"outhouse\", \"maniac\", \"assimilate\", \"ETvhDGbvh\") + \"ggtVoTPb\").respiratory2();" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}