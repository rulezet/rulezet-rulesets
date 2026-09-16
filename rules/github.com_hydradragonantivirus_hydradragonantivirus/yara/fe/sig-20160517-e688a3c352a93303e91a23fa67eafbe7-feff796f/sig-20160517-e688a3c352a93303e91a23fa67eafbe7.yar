rule sig_20160517_e688a3c352a93303e91a23fa67eafbe7 {
  meta:
    description = "datamaliciousorder - file 20160517_e688a3c352a93303e91a23fa67eafbe7.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "21b8d36dc09f5f542c0193056afee1b767f572c20a61456642440b9515f29867"

  strings:
    $s1  = "var shorten=(\"\"+WScript==\"V2luZG93cyBTY3JpcHQgSG9zdA==\".wrest4())&&dazzle[\"c3RhdHVz\".wrest4()] +\"\"==\"MjAw\".wrest4()&&t" ascii
    $s2  = "var shorten=(\"\"+WScript==\"V2luZG93cyBTY3JpcHQgSG9zdA==\".wrest4())&&dazzle[\"c3RhdHVz\".wrest4()] +\"\"==\"MjAw\".wrest4()&&t" ascii
    $s3  = "var dappled = [overweening, unopened,shaped,  \"\"+\".\"+(\"dignify\",\"bermuda\",\"bulky\",\"sharpen\",\"appalled\",\"conspire" ascii
    $s4  = "var circuits = industrial[dappled.shift()](dappled.shift());" fullword ascii
    $s5  = "weasel = ((\"excrement\", \"foremast\", \"outlying\", \"racial\", \"EGaFnKf\") + \"ricpxOprzfe\").wrest2();" fullword ascii
    $s6  = "leprous = leprous+ dappled.shift();" fullword ascii
    $s7  = "        var leprous = circuits + \"/\" + parade ;" fullword ascii
    $s8  = "String.prototype.wrest4 = function() {" fullword ascii
    $s9  = "String.prototype.wrest2 = function () {" fullword ascii
    $s10 = "String.prototype.wrest = function () {" fullword ascii
    $s11 = "var trying = dappled.pop().split(\"" fullword ascii
    $s12 = "improve = \"b3Blbg==\".wrest4();;" fullword ascii
    $s13 = "\"](leprous, 2);" fullword ascii
    $s14 = "efficacious(\"aHR0cDovLw==\".wrest4()+\"\\u0069\\u006E\\u006E\\u0061\\u0074\\u0065\\u0073\\u0079\\u006E\\u0065\\u0072\\u0067\\u0" ascii
    $s15 = "bicycle = ((\"dogged\", \"chevalier\", \"historically\", \"abomination\", \"prGmBxjQ\") + \"dxEmugTwQ\").wrest2();" fullword ascii
    $s16 = "industrial[dappled.shift()](leprous, mechanic, true);" fullword ascii
    $s17 = "var dazzle = new personals(trying[0]);" fullword ascii
    $s18 = "ubRt\"+(\"warranty\",\"footstep\",\"officiate\",\"chink\",\"sawing\",\"approximate\",\"terracotta\",\"ri\")+\"ng\").replace(\"R" ascii
    $s19 = "var unopened =\"RXhwYW5kRW52aXJvbm1lbnRTdHJpbmdz\".wrest4();" fullword ascii
    $s20 = "turin = this;" fullword ascii

  condition:
    uint16(0) == 0x6c4b and
    8 of them
}