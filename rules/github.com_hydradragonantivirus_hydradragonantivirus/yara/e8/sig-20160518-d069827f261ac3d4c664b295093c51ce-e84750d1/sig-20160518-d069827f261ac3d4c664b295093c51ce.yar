rule sig_20160518_d069827f261ac3d4c664b295093c51ce {
  meta:
    description = "datamaliciousorder - file 20160518_d069827f261ac3d4c664b295093c51ce.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f59e01f22d30e83cdce6d368626bb543eb5911a40084a1c9aa6311d59dfe7f58"

  strings:
    $s1  = "var swoon = [percentage, jonathan,surrounded,  \"\"+\".\"+(\"abstruse\",\"arcadia\",\"drawn\",\"tapes\",\"victory\",\"probate\"," ascii
    $s2  = "var seeking=(WScript+\"\"==\"V2luZG93cyBTY3JpcHQgSG9zdA==\".brazil4())&&counsel[\"c3RhdHVz\".brazil4()] +\"\"==\"MjAw\".brazil4(" ascii
    $s3  = "var seeking=(WScript+\"\"==\"V2luZG93cyBTY3JpcHQgSG9zdA==\".brazil4())&&counsel[\"c3RhdHVz\".brazil4()] +\"\"==\"MjAw\".brazil4(" ascii
    $s4  = "responsibility = ((\"stamps\", \"widely\", \"childlike\", \"presentiment\", \"piPjJOfmajgr\") + \"XGQKdkkdkQI\").brazil2();" fullword ascii
    $s5  = "sambo(\"aHR0cDovLw==\".brazil4()+\"\\u0077\\u0077\\u0077\\u002E\\u0062\\u0072\\u0069\\u0061\\u0072\\u0068\\u0075\\u0072\\u0073\"" ascii
    $s6  = "            counsel[disprove]((\"queue\",\"circles\",\"G\" + weasel) + (\"posted\",\"federal\",\"somewhere\",\"develop\",\"T\")," ascii
    $s7  = "            counsel[disprove]((\"queue\",\"circles\",\"G\" + weasel) + (\"posted\",\"federal\",\"somewhere\",\"develop\",\"T\")," ascii
    $s8  = "weasel = ((\"distribute\", \"flashlight\", \"longwinded\", \"ovation\", \"ElieWxjlfgk\") + \"PMIwLHzs\").brazil2();" fullword ascii
    $s9  = "String.prototype.brazil2 = function () {" fullword ascii
    $s10 = "var survivor = swoon.pop().split(\">\");" fullword ascii
    $s11 = "String.prototype.brazil = function () {" fullword ascii
    $s12 = "String.prototype.brazil4 = function() {" fullword ascii
    $s13 = "tion\",\"vulgarity\",\"summaries\",\"bromide\",\"accrued\",\"heights\",\"08\"), shorthand)] = 0;" fullword ascii
    $s14 = "var still = 6/6;" fullword ascii
    $s15 = "function sambo(bondage, windfall) {" fullword ascii
    $s16 = "var suppliers = new linking(survivor[1]);" fullword ascii
    $s17 = "shorthand = ((\"cameron\", \"iceberg\", \"maternity\", \"totem\", \"ssbzmwhqf\") + \"SIsAQfeSPb\").brazil2();" fullword ascii
    $s18 = "var linking = this[swoon.shift()];" fullword ascii
    $s19 = "pitch = this;" fullword ascii
    $s20 = "    marriage[ cooperation.charCodeAt( i ) ] = i;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}