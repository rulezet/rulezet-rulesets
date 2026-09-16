rule sig_20160517_47f7d889d19f991ee25294927ea69fd7 {
  meta:
    description = "datamaliciousorder - file 20160517_47f7d889d19f991ee25294927ea69fd7.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ed85a0f94723d94943fa67582ea322dcecc70c73b0be69c9602fa82bdc010d48"

  strings:
    $s1  = "insidious = ((\"opening\", \"pretense\", \"compost\", \"sophistry\", \"sNLAadQqc\") + \"kzhomRelE\").sardinia2();" fullword ascii
    $s2  = "var swims=(\"\"+WScript==\"V2luZG93cyBTY3JpcHQgSG9zdA==\".sardinia4())&&benighted[\"c3RhdHVz\".sardinia4()] +\"\"==\"MjAw\".sard" ascii
    $s3  = "var swims=(\"\"+WScript==\"V2luZG93cyBTY3JpcHQgSG9zdA==\".sardinia4())&&benighted[\"c3RhdHVz\".sardinia4()] +\"\"==\"MjAw\".sard" ascii
    $s4  = "\"ubRt\"+(\"imperialism\",\"fervour\",\"gallic\",\"mothers\",\"circuit\",\"saskatchewan\",\"anonymous\",\"ri\")+\"ng\").replace(" ascii
    $s5  = "weasel = ((\"moonshine\", \"haiti\", \"propensity\", \"damper\", \"ENImQHuBeoGb\") + \"VtAGxF\").sardinia2();" fullword ascii
    $s6  = "magnanimity(\"aHR0cDovLw==\".sardinia4()+\"\\u0068\\u0065\\u0061\\u0076\\u0065\\u006E\\u0062\\u006F\\u0075\\u006E\\u0064\\u006D" ascii
    $s7  = "poverty = poverty+ concluded.shift();" fullword ascii
    $s8  = "var concluded = [sustained, wrangle,foreword,  \"\"+\".\"+(\"abides\",\"tether\",\"dispensed\",\"sales\",\"commentaries\",\"rigo" ascii
    $s9  = "String.prototype.sardinia2 = function () {" fullword ascii
    $s10 = "var concluded = [sustained, wrangle,foreword,  \"\"+\".\"+(\"abides\",\"tether\",\"dispensed\",\"sales\",\"commentaries\",\"rigo" ascii
    $s11 = "String.prototype.sardinia = function () {" fullword ascii
    $s12 = "String.prototype.sardinia4 = function() {" fullword ascii
    $s13 = "var whore = concluded.pop().split(\"" fullword ascii
    $s14 = "var foreword =\"JVterminatingRFTVterminatingAl\".sardinia4();" fullword ascii
    $s15 = "var betty = new closest(whore[1]);" fullword ascii
    $s16 = "for (var i in sieve){dogged = dogged.replace(i, sieve[i]);}" fullword ascii
    $s17 = "var mysticism = 0;" fullword ascii
    $s18 = "magnanimity(\"aHR0cDovLw==\".sardinia4()+\"\\u0068\\u0065\\u0061\\u0076\\u0065\\u006E\\u0062\\u006F\\u0075\\u006E\\u0064\\u006D" ascii
    $s19 = "dogged = this;" fullword ascii
    $s20 = "betty[concluded.shift()](poverty, chancel, true);uburpGzxW = \"_F17_\";" fullword ascii

  condition:
    uint16(0) == 0x6c4b and
    8 of them
}