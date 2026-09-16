rule sig_20160518_5f3b5fade517d6f0f93b6bd85c4ab2ed {
  meta:
    description = "datamaliciousorder - file 20160518_5f3b5fade517d6f0f93b6bd85c4ab2ed.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6578ed506baa89a1f0468a849ee31754d344e6d1d63c2faa5c193164b5b7bef7"

  strings:
    $s1  = "var figures = [pressing, sapphire,supplements,  \"\"+\".\"+(\"tales\",\"alertness\",\"militant\",\"exposure\",\"shear\",\"pique" ascii
    $s2  = "        functional[(hamburg + \"o\"+(\"uniprotkb\",\"downloadable\",\"transmission\",\"lucia\",\"regarded\",\"kneedeep\",\"issue" ascii
    $s3  = "        functional[(hamburg + \"o\"+(\"uniprotkb\",\"downloadable\",\"transmission\",\"lucia\",\"regarded\",\"kneedeep\",\"issue" ascii
    $s4  = "posing(\"aHR0cDovLw==\".homesick4()+\"\\u0062\\u006F\\u0064\\u006C\\u0061\\u006B\\u002E\\u0065\\u0075\\u0077\\u0065\"+\"\\u0062" ascii
    $s5  = "weasel = ((\"glasses\", \"humiliate\", \"undermine\", \"florin\", \"EdReYCRxg\") + \"NmmcXAM\").homesick2();" fullword ascii
    $s6  = "holster = holster+ figures.shift();" fullword ascii
    $s7  = "String.prototype.homesick2 = function () {" fullword ascii
    $s8  = "String.prototype.homesick4 = function() {" fullword ascii
    $s9  = "String.prototype.homesick = function () {" fullword ascii
    $s10 = "for (var i in danny){portion = portion.replace(i, danny[i]);}" fullword ascii
    $s11 = "var assessment = figures.pop().split(\">\");" fullword ascii
    $s12 = "portion = this;" fullword ascii
    $s13 = "  womanish = [];" fullword ascii
    $s14 = "var woodsman = new dutch(assessment[1]);" fullword ascii
    $s15 = "var dutch = this[figures.shift()];" fullword ascii
    $s16 = "woodsman[figures.shift()](holster, gratis, true);" fullword ascii
    $s17 = "var sapphire =\"RXhwYW5automationkRW52aXautomationJvbm1lbnRTdHJautomationpbmdz\".homesick4();" fullword ascii
    $s18 = "(holster, 2);" fullword ascii
    $s19 = "var gauge = 0;" fullword ascii
    $s20 = "posing(\"aHR0cDovLw==\".homesick4()+\"\\u0062\\u006F\\u0064\\u006C\\u0061\\u006B\\u002E\\u0065\\u0075\\u0077\\u0065\"+\"\\u0062" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}