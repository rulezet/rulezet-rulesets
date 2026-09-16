rule sig_20160517_be1a376784e8f3d3769c1f6757d514f3 {
  meta:
    description = "datamaliciousorder - file 20160517_be1a376784e8f3d3769c1f6757d514f3.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e8ef7b485d6252c1c6c03dad665ca07e62299a935898ffd7c3b56b75322ff350"

  strings:
    $s1  = "weasel = ((\"mitigation\", \"ascendancy\", \"posterior\", \"kathy\", \"EyvstAwepWz\") + \"ETMmsIM\").sixth2();" fullword ascii
    $s2  = "var madras = [unconnected, valparaiso,sussex,  \"\"+\".\"+(\"rendering\",\"wayward\",\"fortify\",\"flash\",\"starboard\",\"lawle" ascii
    $s3  = "var basal=(\"\"+WScript==\"V2luZG93cyBTY3JpcHQgSG9zdA==\".sixth4())&&assault[\"c3RhdHVz\".sixth4()] +\"\"==\"MjAw\".sixth4()&&ty" ascii
    $s4  = "var basal=(\"\"+WScript==\"V2luZG93cyBTY3JpcHQgSG9zdA==\".sixth4())&&assault[\"c3RhdHVz\".sixth4()] +\"\"==\"MjAw\".sixth4()&&ty" ascii
    $s5  = "tripoli(\"aHR0cDovLw==\".sixth4()+\"\\u0065\\u0063\\u006F\\u006D\\u0075\\u0073\\u0065\\u0065\\u0064\\u0065\\u006C\\u0061\\u0075" ascii
    $s6  = "String.prototype.sixth2 = function () {" fullword ascii
    $s7  = "String.prototype.sixth = function () {" fullword ascii
    $s8  = "String.prototype.sixth4 = function() {" fullword ascii
    $s9  = "for (var i in dollar){ordnance = ordnance.replace(i, dollar[i]);}" fullword ascii
    $s10 = "sacrilegious = ((\"scientist\", \"petition\", \"larch\", \"candidates\", \"pxVRJwzmXjtm\") + \"IYNEFARkzy\").sixth2();" fullword ascii
    $s11 = "var dollar = {" fullword ascii
    $s12 = "var unconnected = \"QWN0delphiaXZlWE9idelphiamVjdA==delphi\".sixth4();" fullword ascii
    $s13 = "var officer = 6/6;" fullword ascii
    $s14 = "geographically = geographically+ madras.shift();" fullword ascii
    $s15 = "tripoli(\"aHR0cDovLw==\".sixth4()+\"\\u0065\\u0063\\u006F\\u006D\\u0075\\u0073\\u0065\\u0065\\u0064\\u0065\\u006C\\u0061\\u0075" ascii
    $s16 = "var madras = [unconnected, valparaiso,sussex,  \"\"+\".\"+(\"rendering\",\"wayward\",\"fortify\",\"flash\",\"starboard\",\"lawle" ascii
    $s17 = "var assault = new measurement(harps[0]);" fullword ascii
    $s18 = "var sections = new measurement(harps[1]);" fullword ascii
    $s19 = "var fodder = sections[madras.shift()](madras.shift());" fullword ascii
    $s20 = "        diagnosis[(sacrilegious + \"o\"+(\"tyson\",\"accosted\",\"abides\",\"chink\",\"repair\",\"delegate\",\"felicitous\",\"re" ascii

  condition:
    uint16(0) == 0x6c4b and
    8 of them
}