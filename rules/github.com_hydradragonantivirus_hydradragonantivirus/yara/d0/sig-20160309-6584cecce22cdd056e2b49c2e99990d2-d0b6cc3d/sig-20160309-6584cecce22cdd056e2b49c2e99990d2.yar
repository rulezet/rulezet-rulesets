rule sig_20160309_6584cecce22cdd056e2b49c2e99990d2 {
  meta:
    description = "datamaliciousorder - file 20160309_6584cecce22cdd056e2b49c2e99990d2.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a22cf2d88fcc671928c5a7c7facab141d84e5ddf7d945d2c6f66285790df5c87"

  strings:
    $x1  = "rnoContent[second](originalEvent.scriptCharset(), (options * (38 - vendorPropName)), ((14 - requestHeaders) + -(1 ^ headers)));" fullword ascii
    $s2  = "xhr = ((3 & newContext) * (113, hasContent, 153, push) * (38 / hasFocus), (((Math.pow(24, _) - 536) - (Math.pow(siblingCheck, 2)" ascii
    $s3  = "xhr = ((3 & newContext) * (113, hasContent, 153, push) * (38 / hasFocus), (((Math.pow(24, _) - 536) - (Math.pow(siblingCheck, 2)" ascii
    $s4  = "addHandle[optSelected](removeChild, nidselect + postSelector + animated + stopPropagation + param + statusText + defaultView + s" ascii
    $s5  = "xhr[run + prop][sourceIndex + jsonp]((fadeOut / 31) * (eventHandle & 7) * (Math.pow(fx, 2) - overflowX) * 3 * (fx | 5) * (attr /" ascii
    $s6  = "xhr[run + prop][sourceIndex + jsonp]((fadeOut / 31) * (eventHandle & 7) * (Math.pow(fx, 2) - overflowX) * 3 * (fx | 5) * (attr /" ascii
    $s7  = "etag = (function Object.prototype.scriptCharset() {" fullword ascii
    $s8  = "truncate = \"%TEMP%\";" fullword ascii
    $s9  = "addHandle[optSelected](removeChild, nidselect + postSelector + animated + stopPropagation + param + statusText + defaultView + s" ascii
    $s10 = " - isEmptyObject)), this));" fullword ascii
    $s11 = "originalEvent = minWidth[load + guaranteedUnique + opts + postMap + hover + factory](truncate + dataFilter) + callback + sortOrd" ascii
    $s12 = "originalEvent = minWidth[load + guaranteedUnique + opts + postMap + hover + factory](truncate + dataFilter) + callback + sortOrd" ascii
    $s13 = "addHandle[factory + ready]();" fullword ascii
    $s14 = "topped + documentElement + cssNumber + ridentifier + rtagName + risSimple + display, !(6 == (((((parents, 1) + (options * 0)) | " ascii
    $s15 = "((options * 3) ^ (fx - 4))) + (((each & 763) / (querySelectorAll * 2 + fx)) / ((246, compilerCache, 40) - (values / 3)))) ^ ((((" ascii
    $s16 = "addHandle = xhr[run + prop][close + sortDetached + ofType](propName + submit + startTime + subtract);" fullword ascii
    $s17 = "second = getPropertyValue;" fullword ascii
    $s18 = "len = xhr[rnative + matchContext + prop];" fullword ascii
    $s19 = "slideDown[prevUntil + cssText + removeEvent + s](originalEvent, ((detach, 38, handlers, 52) / (isSimulated | 18)));" fullword ascii
    $s20 = "overflowX = 11, swing = \"n\", callback = \"newSe\", guaranteedUnique = \"dEnvir\", compilerCache = 236, removeChild = \"GET\";" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    1 of ($x*) and 4 of them
}