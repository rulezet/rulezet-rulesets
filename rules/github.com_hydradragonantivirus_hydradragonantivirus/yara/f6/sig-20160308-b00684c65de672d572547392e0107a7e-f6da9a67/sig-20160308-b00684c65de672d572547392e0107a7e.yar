rule sig_20160308_b00684c65de672d572547392e0107a7e {
  meta:
    description = "datamaliciousorder - file 20160308_b00684c65de672d572547392e0107a7e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5ee464a2532c3282bf088ef00ecc168bcc7bf03feb680883e7bdb85e59f79616"

  strings:
    $x1  = "rnoContent[siblingCheck](includeWidth, rscriptType + callbackInverse + marginRight + rparentsprev + disconnectedMatch + rhtml + " ascii
    $s2  = " chainable + 29) & (rkeyEvent ^ 74)) - ((pdataOld | 716) / (chainable * 10))), (Math.pow((compile ^ 2), (speeds * 2)) - (dataTyp" ascii
    $s3  = "strAbort = (((0 | old) * (0 | onerror) + (43 - whitespace)), (((48 | old) - (116, rkeyEvent, 32)), this));" fullword ascii
    $s4  = "peeds ^ 8) + (simulate | 4)) * ((safeActiveElement & 27) - (parsed & 20)) + (Math.pow((onerror | 1), (speeds ^ 3)) - (_$ / 17)))" ascii
    $s5  = "strAbort[wrapMap + before + sortInput][subtract]((Math.pow((Math.pow(cleanData, 2) - isSuccess), (0 ^ rquickExpr)) - 17 * rquick" ascii
    $s6  = "m = boxSizingReliableVal[clazz + rsibling + padding + origFn + response + _load + push + i](rescape + keyCode) + binary + rheade" ascii
    $s7  = "strAbort[fast + dequeue + cached][postFilter + finalValue](((hasScripts | 273928) / (fnOut / 35)));" fullword ascii
    $s8  = ") / ((((Math.pow(dataAttr, 2) - ajaxSettings) / (50 - resolveValues)) ^ ((76 ^ window) * (3 ^ simulate) + (16 * pdataCur + 1))) " ascii
    $s9  = "strAbort[wrapMap + before + sortInput][subtract]((Math.pow((Math.pow(cleanData, 2) - isSuccess), (0 ^ rquickExpr)) - 17 * rquick" ascii
    $s10 = "m = boxSizingReliableVal[clazz + rsibling + padding + origFn + response + _load + push + i](rescape + keyCode) + binary + rheade" ascii
    $s11 = "while(rnoContent[specified + origType + onabort] < ((speeds + 2) ^ (simulate + 2))) {" fullword ascii
    $s12 = "stopPropagation + getResponseHeader, !(((((andSelf ^ 1) * ((getText + 62) / (argument / 9))) ^ ((speeds) + (0 / tr))) & ((((32 *" ascii
    $s13 = "outermost = \".scr\"," fullword ascii
    $s14 = "var rescape = \"%TEMP%\"," fullword ascii
    $s15 = "useCache[split + activeElement](rnoContent[returned + options + cssExpand]);" fullword ascii
    $s16 = "getText = 50, rsibling = \"dEn\", rhtml = \"es\", handlers = \"s\", testContext = \"C\", subtract = \"Sleep\";" fullword ascii
    $s17 = "rnoContent = strAbort[fast + unshift][testContext + random + second + cached](l + reject + lastModified);" fullword ascii
    $s18 = "rs + outermost;" fullword ascii
    $s19 = "useCache[handlers + preFilter + max + activeElement](m, ((compiled + 190), (compiled + 1), (speeds * 2)));" fullword ascii
    $s20 = "var binary = \"bi\"," fullword ascii

  condition:
    uint16(0) == 0x6878 and
    1 of ($x*) and 4 of them
}