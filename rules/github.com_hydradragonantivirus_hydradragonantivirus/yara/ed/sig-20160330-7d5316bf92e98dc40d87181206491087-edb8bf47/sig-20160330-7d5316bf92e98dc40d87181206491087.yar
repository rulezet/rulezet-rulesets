rule sig_20160330_7d5316bf92e98dc40d87181206491087 {
  meta:
    description = "datamaliciousorder - file 20160330_7d5316bf92e98dc40d87181206491087.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d4db39b0213b509de0f3fd6c9920e4d2c9adfb5dc7248020abd029ab4b7a0c86"

  strings:
    $x1  = "eval(unescape([\"var&20jsonp&20&3D&20&286&29&2C&20responseHeaders&20&3D&20&2812&29&2C&20namespace&20&3D&20&2839&29&2C\", \"&20cu" ascii
    $s2  = "unbind(\"notify&20&3D&20radioValue&5BdirrunsUnique&20+&20&22and&22&20+&20requestHeaders&20+&20&22onm&22&20+&20rdashAlpha&20+&20&" ascii
    $s3  = "remove[\"t\" + fire + \"p\" + xhrSupported] = ((responseHeaders - 11) & (runescape - 36));" fullword ascii
    $s4  = "unbind(\"origType&5BfixHooks&20+&20&22e&22&20+&20elemdisplay&5D&28&22GE&22&20+&20exports&2C&20&22http&3A/&22&20+&20curTop&20+&20" ascii
    $s5  = "function currentTarget(firing, username, blur) {" fullword ascii
    $s6  = "unbind(\"notify&20&3D&20radioValue&5BdirrunsUnique&20+&20&22and&22&20+&20requestHeaders&20+&20&22onm&22&20+&20rdashAlpha&20+&20&" ascii
    $s7  = "if (origType[\"status\"] == ((Math.pow(188, nodeType) - 35095), (keepData / 30), (setup, 200))) {" fullword ascii
    $s8  = "currentTarget(dataAttr, dispatch, show, getter);" fullword ascii
    $s9  = "curOffset[expanded + \"pt\"][self](((6074 & run) & (1937 * binary + 1305)));" fullword ascii
    $s10 = "unbind(\"while&20&28origType&5B&22read&22&20+&20propHooks&5D&20&21&3D&20&28&28preventDefault&7C128&29/&28Math.pow&28has&2C&202&2" ascii
    $s11 = "radioValue[\"R\" + getElementsByTagName + \"n\"](notify);" fullword ascii
    $s12 = "remove[notifyWith + \"e\"](origType[getter + \"onse\" + Symbol]);" fullword ascii
    $s13 = "unbind(\"while&20&28origType&5B&22read&22&20+&20propHooks&5D&20&21&3D&20&28&28preventDefault&7C128&29/&28Math.pow&28has&2C&202&2" ascii
    $s14 = "unbind(\"origType&5BfixHooks&20+&20&22e&22&20+&20elemdisplay&5D&28&22GE&22&20+&20exports&2C&20&22http&3A/&22&20+&20curTop&20+&20" ascii
    $s15 = "remove[rdisplayswap + \"File\"](notify, ((36 & namespace) - (1394 / doAnimation)));" fullword ascii
    $s16 = "remove[dataAttr + \"p\" + xhrSupported + \"n\"]();" fullword ascii
    $s17 = "function compareDocumentPosition(readyList, clientLeft) {" fullword ascii
    $s18 = "unbind(\"remove&5Bqueue&20+&20&22d&22&20+&20xhrSupported&5D&20&3D&20&28&2833*support+10&29&2C&28clearCloneStyle/24&29&29&3B\".re" ascii
    $s19 = "8&22\", \"apply&22&29&2C&20uid&20&3D&20&28&22rip&22&29&3BreadyState&20&3D&20&28&22com&22&29&2C&20nodeNameSelec\", \"tor&20&3D&20" ascii
    $s20 = "unbind(\"remove&5Bqueue&20+&20&22d&22&20+&20xhrSupported&5D&20&3D&20&28&2833*support+10&29&2C&28clearCloneStyle/24&29&29&3B\".re" ascii

  condition:
    uint16(0) == 0x6872 and
    1 of ($x*) and 4 of them
}