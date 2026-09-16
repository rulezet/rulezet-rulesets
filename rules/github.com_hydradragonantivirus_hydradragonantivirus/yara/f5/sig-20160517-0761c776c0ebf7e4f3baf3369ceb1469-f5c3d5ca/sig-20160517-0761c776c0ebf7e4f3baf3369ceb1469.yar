rule sig_20160517_0761c776c0ebf7e4f3baf3369ceb1469 {
  meta:
    description = "datamaliciousorder - file 20160517_0761c776c0ebf7e4f3baf3369ceb1469.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b6ae59748960f0f6d20f162fc57fe807d2cde40c6ef2c1a4c32a9c97d5309758"

  strings:
    $s1  = "var characteristics=(\"\"+WScript==\"V2luZG93cyBTY3JpcHQgSG9zdA==\".shore4())&&precipitous[\"c3RhdHVz\".shore4()] +\"\"==\"MjAw" ascii
    $s2  = "var characteristics=(\"\"+WScript==\"V2luZG93cyBTY3JpcHQgSG9zdA==\".shore4())&&precipitous[\"c3RhdHVz\".shore4()] +\"\"==\"MjAw" ascii
    $s3  = "tamper = ((\"municipal\", \"chevy\", \"dissemble\", \"suspension\", \"pWBgReJvphej\") + \"vipthVpuLYp\").shore2();" fullword ascii
    $s4  = "            precipitous[associates]((\"sense\",\"operating\",\"G\" + weasel) + (\"icons\",\"bondage\",\"inappropriate\",\"reques" ascii
    $s5  = "piecemeal = piecemeal+ agreeing.shift();" fullword ascii
    $s6  = "            precipitous[associates]((\"sense\",\"operating\",\"G\" + weasel) + (\"icons\",\"bondage\",\"inappropriate\",\"reques" ascii
    $s7  = "blurred(\"aHR0cDovLw==\".shore4()+\"\\u0066\\u0069\\u0074\\u006D\\u0061\\u0067\\u002E\\u006F\\u0072\\u0067\"+\"\\u002F\\u0037\\u" ascii
    $s8  = "String.prototype.shore2 = function () {" fullword ascii
    $s9  = "String.prototype.shore = function () {" fullword ascii
    $s10 = "String.prototype.shore4 = function() {" fullword ascii
    $s11 = "var experimentally = new turkey(photoshop[1]);" fullword ascii
    $s12 = "var precipitous = new turkey(photoshop[0]);" fullword ascii
    $s13 = "var turkey = this[agreeing.shift()];" fullword ascii
    $s14 = "weasel = ((\"carlo\", \"brunette\", \"checkout\", \"looking\", \"EzavPJwPCt\") + \"kkssVGBP\").shore2();" fullword ascii
    $s15 = "        micro[(tamper + \"o\"+(\"depict\",\"texas\",\"inversion\",\"restive\",\"garrulous\",\"bailey\",\"collectors\",\"easier\"" ascii
    $s16 = "var agreeing = [inside, latina,meritorious,  \"\"+\".\"+(\"thumbnail\",\"capital\",\"storage\",\"individual\",\"incognito\",\"ep" ascii
    $s17 = "        var micro = new turkey(((\"simpson\",\"effectiveness\",\"banns\",\"garrulous\",\"controls\",\"philanthropist\",\"puppy\"" ascii
    $s18 = "var inside = \"QWN0imbibeaXZlWE9iimbibeamVjdA==imbibe\".shore4();" fullword ascii
    $s19 = "ulwark, false);" fullword ascii
    $s20 = "function blurred(bulwark, announcements) {" fullword ascii

  condition:
    uint16(0) == 0x6c4b and
    8 of them
}