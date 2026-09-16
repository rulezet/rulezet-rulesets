rule sig_20160309_f5c1d707c20a81544e7484a9e585be1e {
  meta:
    description = "datamaliciousorder - file 20160309_f5c1d707c20a81544e7484a9e585be1e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5516af7bb3f21a42c7c500e922d5a66c2bcb00cf3d607e052466a781ee85563b"

  strings:
    $x1  = "statusCode[raw](parseOnly, attrs + swing + rheaders + display + binary + p + click + sibling + cssPrefixes + off + currentTarget" ascii
    $s2  = ", (3 | seekingTransport), (125, compile, 1))), (Math.pow((((simple + 104) / (Math.pow(contentType, 2) - offset)) & ((60 - XMLHtt" ascii
    $s3  = "option[host + emptyStyle + tag + emptyGet] = ((1 & rclickable) & (42 - removeEventListener));" fullword ascii
    $s4  = "statusCode[raw](parseOnly, attrs + swing + rheaders + display + binary + p + click + sibling + cssPrefixes + off + currentTarget" ascii
    $s5  = "slideUp = fontWeight[rxhtmlTag + timeout + slideDown + replaceAll + types + getText + password + remove](clazz + border) + inser" ascii
    $s6  = "* (appendTo + 107) & (Math.pow((isNumeric, 200), (location * 2)) - (rheader)))), ((Math.pow((6 + location), (2 & blur)) - (19 ^ " ascii
    $s7  = "show = statusCode[disableScript + getAllResponseHeaders + scrollTo + unqueued];" fullword ascii
    $s8  = "postFilter[rmouseEvent](slideUp.owner(), ((rclickable | 35) - beforeSend * 5), ((css - 21) - (curPosition, 49, duration)));" fullword ascii
    $s9  = "slideUp = fontWeight[rxhtmlTag + timeout + slideDown + replaceAll + types + getText + password + remove](clazz + border) + inser" ascii
    $s10 = " 3))) - ((dispatch * 2 * dispatch * (644 / rnoContent) + (3 | rclickable)), ((891 / params) * (8 / XMLHttpRequest) + (97, locati" ascii
    $s11 = "matcherIn = dataType[mouseleave + newUnmatched][guid + ajaxSettings + fixInput](cacheURL + removeData + colgroup + pipe + rheade" ascii
    $s12 = "matcherIn = dataType[mouseleave + newUnmatched][guid + ajaxSettings + fixInput](cacheURL + removeData + colgroup + pipe + rheade" ascii
    $s13 = "dataType = (((1232 / xhrSuccessStatus) + (3 + dispatch)), (((Math.pow(224, dispatch) - 49852) / (rdashAlpha / 31)), this));" fullword ascii
    $s14 = "matcherIn[remove + noop + opacity + b](slideUp, ((15 * dispatch + 14) - (removeEventListener | 40)));" fullword ascii
    $s15 = "password = \"ng\";" fullword ascii
    $s16 = ")) | ((117 + css) - (5 * dispatch + 2)))), ((((noConflict * 4 + location) + (Math.pow(60, dispatch) - 3483))) & ((location * 2) " ascii
    $s17 = "location = 1, host = \"posi\", contentType = 17, disableScript = \"Respo\", bool = \"ateOb\";" fullword ascii
    $s18 = "pipe = \".Strea\";" fullword ascii
    $s19 = "statusCode = dataType[button + headers + emptyStyle][Callbacks + cssProps + tfoot + factory](doAnimation + callbackName + disabl" ascii
    $s20 = "statusCode = dataType[button + headers + emptyStyle][Callbacks + cssProps + tfoot + factory](doAnimation + callbackName + disabl" ascii

  condition:
    uint16(0) == 0x6176 and
    1 of ($x*) and 4 of them
}