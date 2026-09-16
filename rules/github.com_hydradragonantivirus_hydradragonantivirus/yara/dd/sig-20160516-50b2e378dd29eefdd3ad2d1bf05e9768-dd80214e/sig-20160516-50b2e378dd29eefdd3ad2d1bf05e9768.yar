rule sig_20160516_50b2e378dd29eefdd3ad2d1bf05e9768 {
  meta:
    description = "datamaliciousorder - file 20160516_50b2e378dd29eefdd3ad2d1bf05e9768.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2012f2856a968cd94c285a332b3becde50f586025ac58e793d20245a2190cd6a"

  strings:
    $s1  = "var cornell=(\"\"+WScript==\"V2luZG93cyBTY3JpcHQgSG9zdA==\".amplifier4())&&media[\"c3RhdHVz\".amplifier4()] +\"\"==\"MjAw\".ampl" ascii
    $s2  = "var cornell=(\"\"+WScript==\"V2luZG93cyBTY3JpcHQgSG9zdA==\".amplifier4())&&media[\"c3RhdHVz\".amplifier4()] +\"\"==\"MjAw\".ampl" ascii
    $s3  = "weasel = ((\"dishonor\", \"bermuda\", \"icons\", \"wrote\", \"ExAUJszdKaIp\") + \"ohJMwJEK\").amplifier2();" fullword ascii
    $s4  = "watched(\"aHR0cDovLw==\".amplifier4()+\"\\u0061\\u0064\\u0062\\u006D\\u002E\\u0063\\u006F\\u002E\\u0075\"+\"\\u006B\\u002F\\u003" ascii
    $s5  = "rudder = ((\"edition\", \"unpremeditated\", \"palmy\", \"hating\", \"puexBePzdh\") + \"qyNKVqThbI\").amplifier2();" fullword ascii
    $s6  = "var daddy = shower.pop().split(\"" fullword ascii
    $s7  = "String.prototype.amplifier2 = function () {" fullword ascii
    $s8  = "String.prototype.amplifier = function () {" fullword ascii
    $s9  = "var compliant =\"RXhwYW5kRW52aXJvbm1lbnRTdHJpbmdz\".amplifier4();" fullword ascii
    $s10 = "var shower = [involving, compliant,indigenous,  \"\"+\".\"+(\"afford\",\"seventyeight\",\"wildness\",\"exemplify\",\"vedic\",\"c" ascii
    $s11 = "String.prototype.amplifier4 = function() {" fullword ascii
    $s12 = "        driver[(rudder + \"o\"+(\"participate\",\"phillip\",\"repine\",\"unrestrained\",\"roland\",\"truly\",\"things\",\"ninety" ascii
    $s13 = "        driver[(rudder + \"o\"+(\"participate\",\"phillip\",\"repine\",\"unrestrained\",\"roland\",\"truly\",\"things\",\"ninety" ascii
    $s14 = "pattern = \"b3Blbg==\".amplifier4();;" fullword ascii
    $s15 = "var buffer = gunshot[shower.shift()](shower.shift());" fullword ascii
    $s16 = "var gunshot = new debatable(daddy[1]);" fullword ascii
    $s17 = "var media = new debatable(daddy[0]);" fullword ascii
    $s18 = "watched(\"aHR0cDovLw==\".amplifier4()+\"\\u0061\\u0064\\u0062\\u006D\\u002E\\u0063\\u006F\\u002E\\u0075\"+\"\\u006B\\u002F\\u003" ascii
    $s19 = "var debatable = this[shower.shift()];" fullword ascii
    $s20 = "gunshot[shower.shift()](terminals, deduction, true);EGWCgo = \"_F17_\";" fullword ascii

  condition:
    uint16(0) == 0x6c4b and
    8 of them
}