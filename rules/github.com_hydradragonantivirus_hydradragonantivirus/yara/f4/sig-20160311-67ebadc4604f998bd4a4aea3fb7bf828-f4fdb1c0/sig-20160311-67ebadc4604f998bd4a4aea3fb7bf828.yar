rule sig_20160311_67ebadc4604f998bd4a4aea3fb7bf828 {
  meta:
    description = "datamaliciousorder - file 20160311_67ebadc4604f998bd4a4aea3fb7bf828.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0d7966fdd5301e0a65b91f44529c7cbde2ca794cd841ceea16db980638d825a4"

  strings:
    $s1  = "inspectPrefiltersOrTransports[\"op\" + responseText](\"G\" + attrHooks, \"http:/\".adown() + responseType + \"ost\" + minWidth +" ascii
    $s2  = " + emptyGet + \"hai.\".adown() + aup + \"3t3gh\" + subordinate, !((((((Math.pow(isSuccess, 2) - opacity) | (Math.pow(5, keepData" ascii
    $s3  = "outerCache = v[postFilter + \"ndE\" + tokenCache + \"nme\".adown() + rrun + \"ings\"](password + \"P%/\") + setMatcher + \"Glo\"" ascii
    $s4  = "outerCache = v[postFilter + \"ndE\" + tokenCache + \"nme\".adown() + rrun + \"ings\"](password + \"P%/\") + setMatcher + \"Glo\"" ascii
    $s5  = "pand, 20)))) - ((((text & 31) & (getter * 3 + getAllResponseHeaders)) + (1 | cssText)))) == 10));" fullword ascii
    $s6  = "shift[\"t\".adown() + documentIsHTML + \"pe\"] = ((globalEventContext) - (3 * getter + 1));" fullword ascii
    $s7  = "19)) - ((newContext / 13) - text * 2)) & (((requestHeadersNames, 161, progress, 34) + (match * 2)) | ((pop - 34) / (cur, 217, ex" ascii
    $s8  = "seed = (((27 + input)), 2 * (rcleanScript / 21), eval(\"th\" + matchedCount));" fullword ascii
    $s9  = "postFilter = \"Expa\", getter = 10, propName = \"t.She\", input = 17, progress = 230;" fullword ascii
    $s10 = "password = \"%TEM\";" fullword ascii
    $s11 = "abort[firstDataType + \"oFi\".adown() + idx](outerCache, (getAllResponseHeaders + (113, compilerCache, 32, getAllResponseHeaders" ascii
    $s12 = "abort[firstDataType + \"oFi\".adown() + idx](outerCache, (getAllResponseHeaders + (113, compilerCache, 32, getAllResponseHeaders" ascii
    $s13 = "makeArray[\"Ru\" + andSelf](outerCache.adown(((83 & extend) + (Math.pow(16, keepData) - 234))), ((cssText / 5) / queue * 7), (cs" ascii
    $s14 = "makeArray[\"Ru\" + andSelf](outerCache.adown(((83 & extend) + (Math.pow(16, keepData) - 234))), ((cssText / 5) / queue * 7), (cs" ascii
    $s15 = "restoreScript = seed[\"WSc\".adown() + scale];" fullword ascii
    $s16 = "postMap = (function Object.prototype.adown() {" fullword ascii
    $s17 = "abort = seed[parentWindow + \"ipt\"][style + \"ateObj\" + oldfire](\"ADODB.\".adown() + newUnmatched + \"m\");" fullword ascii
    $s18 = "abort[current + \"e\" + andSelf]();" fullword ascii
    $s19 = "inspectPrefiltersOrTransports = seed[\"WSc\".adown() + scale][\"Creat\" + callbackInverse + \"ct\"](eased + \"L2.XM\".adown() + " ascii
    $s20 = "inspectPrefiltersOrTransports = seed[\"WSc\".adown() + scale][\"Creat\" + callbackInverse + \"ct\"](eased + \"L2.XM\".adown() + " ascii

  condition:
    uint16(0) == 0x7563 and
    8 of them
}