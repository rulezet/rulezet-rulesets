rule sig_20160308_01683bdd14dd918d3ebcbe7f54730c6b {
  meta:
    description = "datamaliciousorder - file 20160308_01683bdd14dd918d3ebcbe7f54730c6b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8c5c5736ce013d2bf6078d277e230b13d69bceb0bedf1b7115bcf8e00a4c421a"

  strings:
    $x1  = "globalEval[isEmptyObject + ajaxTransport](readyState, abort + statusCode + teardown + rtrim + dequeue + manipulationTarget + tim" ascii
    $s2  = "matches = rnumnonpx[xhrFields + password + conditionFn][marginDiv + _evalUrl + elemdisplay](isFunction + fireGlobals + currentTa" ascii
    $s3  = "globalEval[isEmptyObject + ajaxTransport](readyState, abort + statusCode + teardown + rtrim + dequeue + manipulationTarget + tim" ascii
    $s4  = "(36 + radioValue)), (117, token, 136, run)) - ((4281 - opacity)))), (((28 / fxNow) & (37 / (overrideMimeType * 3 + iNoClone))) *" ascii
    $s5  = " 19), ((run + 0) | run)) - ((179720112 / createFxNow) - (20865645 / fire))) / (Math.pow(((Math.pow(12, run) - 128) | (tabIndex +" ascii
    $s6  = "html = oMatchesSelector[prepend + responses + content](rheaders + num + charset);" fullword ascii
    $s7  = "type[fromCharCode] = (scripts - 23);" fullword ascii
    $s8  = "selection[complete](results.ready(), ((handlerQueue / 34) + -iNoClone), ((1 | iNoClone) + -(1 & iNoClone)));" fullword ascii
    $s9  = " 12)), (notifyWith ^ 2)) - ((func) ^ 41 * specialEasing * 2))), ((((width & 127), (requestHeaders ^ 5), (queue * 2 + ajaxExtend)" ascii
    $s10 = "fromCharCode = \"type\", boxSizingReliableVal = \"R\", href = 109, rheaders = \"WScrip\", opacity = 1963, box = \".scr\";" fullword ascii
    $s11 = "matches = rnumnonpx[xhrFields + password + conditionFn][marginDiv + _evalUrl + elemdisplay](isFunction + fireGlobals + currentTa" ascii
    $s12 = "while (globalEval[push + mouseenter + useCache + toSelector] < ((Math.pow(35, run) - 1157), (Math.pow(easing, 2) - _default), (5" ascii
    $s13 = "abort = \"ht\", currentTarget = \".Strea\", pdataOld = 6, rbuggyMatches = 17;" fullword ascii
    $s14 = "while (globalEval[push + mouseenter + useCache + toSelector] < ((Math.pow(35, run) - 1157), (Math.pow(easing, 2) - _default), (5" ascii
    $s15 = "er + addEventListener + isEmptyObject + Data + rtagName + hasDuplicate, !(4 == (((Math.pow(((Math.pow(check, 2) - buildParams) +" ascii
    $s16 = ") * ((64 | deep) / (30 - iNoClone)) + ((9 | parseXML) - (13 + actualDisplay))) - (((93 / dir) + 2) + ((href & 116) / (implementa" ascii
    $s17 = "rnumnonpx = (((217 / dir) * (28 ^ parseHTML) + (2 ^ iNoClone)), (((32 | pdataOld) - (9 + radioValue)), this));" fullword ascii
    $s18 = "overrideMimeType = 12, dirruns = \"%T\", conditionFn = \"pt\", special = \"M\";" fullword ascii
    $s19 = "password = \"cri\";" fullword ascii
    $s20 = "complete = boxSizingReliableVal + includeWidth;" fullword ascii

  condition:
    uint16(0) == 0x7073 and
    1 of ($x*) and 4 of them
}