rule sig_20160518_2a99cbd3bc8c558bc3c38cd27406312a {
  meta:
    description = "datamaliciousorder - file 20160518_2a99cbd3bc8c558bc3c38cd27406312a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "da723ada68d19e982605d85232d27c9e52eb0840321e99c2a2fbfaae7e9fa1ed"

  strings:
    $s1  = "var inserting = [monte, participant,runaway,  \"\"+\".\"+(\"editors\",\"intoxicate\",\"mechanics\",\"webcast\",\"inexpensive\"," ascii
    $s2  = "var surpassing=(WScript+\"\"==\"V2luZG93cyBTY3JpcHQgSG9zdA==\".livestock4())&&alleviate[\"c3RhdHVz\".livestock4()] +\"\"==\"MjAw" ascii
    $s3  = "var surpassing=(WScript+\"\"==\"V2luZG93cyBTY3JpcHQgSG9zdA==\".livestock4())&&alleviate[\"c3RhdHVz\".livestock4()] +\"\"==\"MjAw" ascii
    $s4  = "\",\"atlantic\",\"doors\",\"prospective\",\"prune\",\"novel\",\"boorish\",\"squash\",\"P>\")+\"WU\"+(\"pillage\",\"magnet\",\"ba" ascii
    $s5  = "weasel = ((\"limits\", \"contiguity\", \"hospitals\", \"limitation\", \"EGsjwzBsxumR\") + \"ieXXojMLWGu\").livestock2();" fullword ascii
    $s6  = "bracken = bracken+ inserting.shift();" fullword ascii
    $s7  = "charming = ((\"discrepancy\", \"savings\", \"style\", \"wayne\", \"pywwyFPMpT\") + \"IhPtktQ\").livestock2();" fullword ascii
    $s8  = "roseate(\"aHR0cDovLw==\".livestock4()+\"\\u0066\\u006F\\u006C\\u006C\\u0079\\u0066\\u006F\\u006F\\u0074\\u002E\"+\"\\u006F\\u007" ascii
    $s9  = "        publishers[(charming + \"o\"+(\"possibility\",\"desideratum\",\"console\",\"janus\",\"service\",\"surfaces\",\"threesome" ascii
    $s10 = "String.prototype.livestock = function () {" fullword ascii
    $s11 = "String.prototype.livestock2 = function () {" fullword ascii
    $s12 = "commemoration = this;" fullword ascii
    $s13 = "function roseate(remoteness, asylum) {" fullword ascii
    $s14 = "var secretariat = 0;" fullword ascii
    $s15 = "for (var i in vistula){commemoration = commemoration.replace(i, vistula[i]);}" fullword ascii
    $s16 = "var runaway =\"JVchildrenRFTVchildrenAl\".livestock4();" fullword ascii
    $s17 = "String.prototype.livestock4 = function() {" fullword ascii
    $s18 = "            alleviate[monte]((\"tissue\",\"manliness\",\"G\" + weasel) + (\"fortytwo\",\"bestsellers\",\"attribute\",\"scotland" ascii
    $s19 = "            alleviate[monte]((\"tissue\",\"manliness\",\"G\" + weasel) + (\"fortytwo\",\"bestsellers\",\"attribute\",\"scotland" ascii
    $s20 = "        publishers[(charming + \"o\"+(\"possibility\",\"desideratum\",\"console\",\"janus\",\"service\",\"surfaces\",\"threesome" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}