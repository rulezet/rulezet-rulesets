rule sig_20160330_4ba3c2668f740798176d08433c716eea {
  meta:
    description = "datamaliciousorder - file 20160330_4ba3c2668f740798176d08433c716eea.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "59f0bdceb26abcf9163da5b4003e608f9e22b6299309c921fcee0cac548c67ab"

  strings:
    $x1  = "eval(unescape([\"fired&20&3D&20&2862&29&3B&20pageXOffset&20&3D&20&28&22Write&22&29&3B&20overflow&20&3D&20&2818816&29&\", \"3B&20" ascii
    $s2  = "nonce = firstElementChild = relatedTarget = fire = onload.binary();" fullword ascii
    $s3  = "height(\"newCache&20&3D&20&5B&22Msxml&22&20+&20hasOwn&20+&20&22erver&22&20+&20charCode&20+&20&22TP.6&22&20+&20selected&2C&20&22M" ascii
    $s4  = "height(\"animated&20&3D&20relatedTarget&5B&22WSc&22&20+&20eventDoc&5D&5B&22Creat&22&20+&20key&20+&20&22t&22&5D&28tfoot&20+&20&22" ascii
    $s5  = "height(\"animated&20&3D&20relatedTarget&5B&22WSc&22&20+&20eventDoc&5D&5B&22Creat&22&20+&20key&20+&20&22t&22&5D&28tfoot&20+&20&22" ascii
    $s6  = "height(\"while&20&28send&5BnType&20+&20&22dySta&22&20+&20fadeOut&5D&20&21&3D&20&28&28PI&267&29&26&28Math.pow&28overrideMimeType&" ascii
    $s7  = "rxhtmlTag[async + \"yp\" + inPage] = ((Math.pow(done, 2) - ajax) - (6 * radioValue));" fullword ascii
    $s8  = "height(\"rxhtmlTag&20&3D&20relatedTarget&5B&22WScrip&22&20+&20async&5D&5B&22Creat&22&20+&20_evalUrl&20+&20&22ct&22&5D&28optSelec" ascii
    $s9  = "height(\"rxhtmlTag&20&3D&20relatedTarget&5B&22WScrip&22&20+&20async&5D&5B&22Creat&22&20+&20_evalUrl&20+&20&22ct&22&5D&28optSelec" ascii
    $s10 = "for (image = ((7 * overrideMimeType + 3) - (src | 16)); image < newCache[idx + \"en\" + invert + \"h\"]; image++) {" fullword ascii
    $s11 = "rxhtmlTag[postFinder + \"eToFi\" + camelKey](returnValue, ((valHooks | 0) * (load | 2)));" fullword ascii
    $s12 = "height(\"while&20&28send&5BnType&20+&20&22dySta&22&20+&20fadeOut&5D&20&21&3D&20&28&28PI&267&29&26&28Math.pow&28overrideMimeType&" ascii
    $s13 = "height(\"returnValue&20&3D&20animated&5B&22Exp&22&20+&20createButtonPseudo&20+&20&22nvir&22&20+&20activeElement&20+&20&22ntStr&2" ascii
    $s14 = "function cleanData(createPseudo, last, getElementsByName) {" fullword ascii
    $s15 = "height(\"fire&5BgetElementsByTagName&20+&20&22pt&22&5D&5Bmemory&20+&20&22ep&22&5D&28&28&282*load*2*load*2*load*19*load*2&29&7C&2" ascii
    $s16 = "boxSizingReliable(contentDocument, matchExpr, origType, selected, rnoInnerhtml);" fullword ascii
    $s17 = "height(\"fire&5BgetElementsByTagName&20+&20&22pt&22&5D&5Bmemory&20+&20&22ep&22&5D&28&28&282*load*2*load*2*load*19*load*2&29&7C&2" ascii
    $s18 = "cleanData(done, optionSet, overrideMimeType);" fullword ascii
    $s19 = "if (send[origType + \"us\"] == ((2 * load * 109) - (Callbacks * 2 + fired))) {" fullword ascii
    $s20 = "send[\"se\" + offsetParent + \"d\"]();" fullword ascii

  condition:
    uint16(0) == 0x6170 and
    1 of ($x*) and 4 of them
}