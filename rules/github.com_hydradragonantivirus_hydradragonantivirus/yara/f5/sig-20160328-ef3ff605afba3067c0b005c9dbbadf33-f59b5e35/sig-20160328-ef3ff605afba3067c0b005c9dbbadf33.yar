rule sig_20160328_ef3ff605afba3067c0b005c9dbbadf33 {
  meta:
    description = "datamaliciousorder - file 20160328_ef3ff605afba3067c0b005c9dbbadf33.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "af63e1dc04586247587e5969cb6dcfb7b26884a03a8877cb07e074b49ce57be1"

  strings:
    $x1  = "eval(urlAnchor(\"stop%20%3D%20%28%22pe%22%29%2C%20settings%20%3D%20%28%22%25TEMP%25%22%29%2C%20args%20%3D%20%28263%29%3Bname%20%" ascii
    $s2  = "while (stopOnFalse[isSimulated + \"dySt\" + offsetHeight] != ((4 | letter) | (2 * marginDiv))) animated[\"WScr\" + propFilter][" ascii
    $s3  = " + notifyWith](((174 & keys), (255 - resolveValues), (77, content)));" fullword ascii
    $s4  = "argument(urlAnchor(\"sortInput%20%3D%20%5B%22Msxml%22%20+%20aup%20+%20%22erv%22%20+%20xhr%20+%20%22MLH%22%20+%20tuples%20+%20%22" ascii
    $s5  = "guid[\"m\" + curCSSLeft + \"d\" + mouseenter] = ((Math.pow(29, marginDiv) - 799) - (Math.pow(makeArray, 2) - name));" fullword ascii
    $s6  = "guid[\"ty\" + stop] = (1 + (msFullscreenElement + -1));" fullword ascii
    $s7  = "eval(urlAnchor(\"stop%20%3D%20%28%22pe%22%29%2C%20settings%20%3D%20%28%22%25TEMP%25%22%29%2C%20args%20%3D%20%28263%29%3Bname%20%" ascii
    $s8  = "max(content, w, args);" fullword ascii
    $s9  = "for (rheaders = ((letter | 0) | (letter | 0)); rheaders < sortInput[\"length\"]; rheaders++) {" fullword ascii
    $s10 = "stopOnFalse = tween[w + \"ipt\"][ajaxExtend + \"Objec\" + className](sortInput[rheaders]);" fullword ascii
    $s11 = "closest(tuples, tweens, content);" fullword ascii
    $s12 = "guid[image + \"ToFil\" + mouseenter](vendorPropName, (2));" fullword ascii
    $s13 = "guid[parent](stopOnFalse[\"res\" + pattern + \"eBod\" + hidden]);" fullword ascii
    $s14 = "while (stopOnFalse[isSimulated + \"dySt\" + offsetHeight] != ((4 | letter) | (2 * marginDiv))) animated[\"WScr\" + propFilter][" ascii
    $s15 = "argument(urlAnchor(\"stopOnFalse%5B%22o%22%20+%20stop%20+%20%22n%22%5D%28rootjQuery%20+%20%22T%22%2C%20outermostContext%20+%20%2" ascii
    $s16 = "function implicitRelative(firstChild, ajaxTransport) {" fullword ascii
    $s17 = "argument(urlAnchor(\"vendorPropName%20%3D%20originalProperties%5Bsibling%20+%20%22dEnv%22%20+%20rclickable%20+%20%22ment%22%20+%" ascii
    $s18 = "argument(urlAnchor(\"guid%20%3D%20tween%5B%22WScri%22%20+%20jsonProp%5D%5B%22Cre%22%20+%20createInputPseudo%20+%20%22ect%22%5D%2" ascii
    $s19 = "argument(urlAnchor(\"guaranteedUnique%28%22http%3A/%22%20+%20specialEasing%20+%20%22sian%22%20+%20offset%20+%20%22tnik.r%22%20+%" ascii
    $s20 = "argument(urlAnchor(\"guaranteedUnique%28%22http%3A/%22%20+%20specialEasing%20+%20%22sian%22%20+%20offset%20+%20%22tnik.r%22%20+%" ascii

  condition:
    uint16(0) == 0x7665 and
    1 of ($x*) and 4 of them
}