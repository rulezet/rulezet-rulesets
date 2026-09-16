rule sig_20160517_c38ef8e165d037ac4366650b27b89564 {
  meta:
    description = "datamaliciousorder - file 20160517_c38ef8e165d037ac4366650b27b89564.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e6b8210856466fc614b5ef3b7848acddc9c5125a891ace6e729ec4fa78267607"

  strings:
    $s1  = "postscript = ((\"concentric\", \"tragedian\", \"negligible\", \"competitors\", \"shepByity\") + \"jpNmALq\").abbeys2();" fullword ascii
    $s2  = "ks\",\"shark\",\"blame\",\"terrifying\",\"chromatic\",\"08\"), postscript)] = 0;" fullword ascii
    $s3  = "        unnecessary[(truncheon + \"o\"+(\"brushing\",\"choleric\",\"ineffectual\",\"losses\",\"retinue\",\"player\",\"twentyeigh" ascii
    $s4  = "    stitching[postscript + (\"sweden\",\"smart\",\"end\")]();" fullword ascii
    $s5  = "truncheon = ((\"beauty\", \"seasoned\", \"insignia\", \"preferment\", \"pEhCvCF\") + \"TkcnXwBy\").abbeys2();" fullword ascii
    $s6  = "var funny=(\"\"+WScript==\"V2luZG93cyBTY3JpcHQgSG9zdA==\".abbeys4())&&stitching[\"c3RhdHVz\".abbeys4()] +\"\"==\"MjAw\".abbeys4(" ascii
    $s7  = "var plash =\"RXhwYW5comportkRW52aXcomportJvbm1lbnRTdHJcomportpbmdz\".abbeys4();" fullword ascii
    $s8  = "var funny=(\"\"+WScript==\"V2luZG93cyBTY3JpcHQgSG9zdA==\".abbeys4())&&stitching[\"c3RhdHVz\".abbeys4()] +\"\"==\"MjAw\".abbeys4(" ascii
    $s9  = "var shown = \"QWcomportN0aXZcomportlWE9iacomportmVjdA=comport=\".abbeys4();" fullword ascii
    $s10 = "        var unnecessary = new ungenerous(((\"recline\",\"south\",\"bolton\",\"headlines\",\"farmer\",\"indicate\",\"organization" ascii
    $s11 = "weasel = ((\"practitioners\", \"tenets\", \"louis\", \"zenith\", \"EaOCvMeftqD\") + \"JqVQrdwgM\").abbeys2();" fullword ascii
    $s12 = "whiles(\"aHR0cDovLw==\".abbeys4()+\"\\u0066\\u0070\\u0067\\u002E\\u0063\\u006F\\u006D\\u002E\\u006D\"+\"\\u0079\\u002F\\u0030\\u" ascii
    $s13 = "String.prototype.abbeys2 = function () {" fullword ascii
    $s14 = "String.prototype.abbeys4 = function() {" fullword ascii
    $s15 = "    purposes.blond = purposes.exposed[((\"eightysix\",\"lafayette\",\"message\",\"barry\",\"occupation\",\"engine\",\"motels\"," ascii
    $s16 = "String.prototype.abbeys = function () {" fullword ascii
    $s17 = "        unnecessary[(truncheon + \"o\"+(\"brushing\",\"choleric\",\"ineffectual\",\"losses\",\"retinue\",\"player\",\"twentyeigh" ascii
    $s18 = "antediluvian = this;" fullword ascii
    $s19 = "var burst = 0;" fullword ascii
    $s20 = ",\"00\")+(\"kansas\",\"imagine\",\"envelop\",\"forbes\",\"blanched\",\"shift\",\"blowjob\",\"8i\")+\"tion\").replace(\"0\"+(\"sp" ascii

  condition:
    uint16(0) == 0x6c4b and
    8 of them
}