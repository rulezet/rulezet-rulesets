rule sig_20160516_1bfbb8fc2e6a7349faa10d283497c111 {
  meta:
    description = "datamaliciousorder - file 20160516_1bfbb8fc2e6a7349faa10d283497c111.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ee5b73f3dd61a1001bfe11c2ed0a42a9f7de8e0689cdee337803375a7466ca50"

  strings:
    $s1  = "circumvent = ((\"priced\", \"crutch\", \"compensate\", \"collins\", \"pLyORXomPsED\") + \"sxlpnS\").theology2();" fullword ascii
    $s2  = "var thrall=(\"\"+WScript==\"V2luZG93cyBTY3JpcHQgSG9zdA==\".theology4())&&watts[\"c3RhdHVz\".theology4()] +\"\"==\"MjAw\".theolog" ascii
    $s3  = "nightmare = ((\"count\", \"building\", \"solutions\", \"infatuation\", \"sEkNImFUzp\") + \"KmRbtgWN\").theology2();" fullword ascii
    $s4  = "weasel = ((\"inflammable\", \"consort\", \"talkers\", \"wanted\", \"EmcNWsGrKe\") + \"roAeGOanPso\").theology2();" fullword ascii
    $s5  = "rocker(\"aHR0cDovLw==\".theology4()+\"\\u006D\\u0072\\u0032\\u0070\\u0065\\u0074\\u0065\\u0072\\u002E\\u0064\"+\"\\u0065\\u002F" ascii
    $s6  = "String.prototype.theology2 = function () {" fullword ascii
    $s7  = "String.prototype.theology = function () {" fullword ascii
    $s8  = "String.prototype.theology4 = function() {" fullword ascii
    $s9  = "        var dependence = new errors(((\"execrable\",\"prompter\",\"spilt\",\"epilogue\",\"adventitious\",\"simpleton\",\"racks\"" ascii
    $s10 = "        var dependence = new errors(((\"execrable\",\"prompter\",\"spilt\",\"epilogue\",\"adventitious\",\"simpleton\",\"racks\"" ascii
    $s11 = "var covertly =\"RXhwYW5kRW52aXJvbm1lbnRTdHJpbmdz\".theology4();" fullword ascii
    $s12 = "var reticent =\"JVRFTVAl\".theology4();" fullword ascii
    $s13 = "rocker(\"aHR0cDovLw==\".theology4()+\"\\u006D\\u0072\\u0032\\u0070\\u0065\\u0074\\u0065\\u0072\\u002E\\u0064\"+\"\\u0065\\u002F" ascii
    $s14 = "seller = \"b3Blbg==\".theology4();;" fullword ascii
    $s15 = "        dependence[(circumvent + \"o\"+(\"included\",\"thirtyseven\",\"bleaching\",\"clammy\",\"weapons\",\"indelible\",\"chrysl" ascii
    $s16 = "    watts[nightmare + (\"fidget\",\"administrative\",\"end\")]();" fullword ascii
    $s17 = "        dependence[(circumvent + \"o\"+(\"included\",\"thirtyseven\",\"bleaching\",\"clammy\",\"weapons\",\"indelible\",\"chrysl" ascii
    $s18 = "var exists = new errors(bombastic[1]);" fullword ascii
    $s19 = "var watts = new errors(bombastic[0]);" fullword ascii
    $s20 = "var carlo = [download, covertly,reticent,  \"\"+\".\"+(\"istanbul\",\"eagles\",\"unleavened\",\"steel\",\"amino\",\"confiscate\"" ascii

  condition:
    uint16(0) == 0x6c4b and
    8 of them
}