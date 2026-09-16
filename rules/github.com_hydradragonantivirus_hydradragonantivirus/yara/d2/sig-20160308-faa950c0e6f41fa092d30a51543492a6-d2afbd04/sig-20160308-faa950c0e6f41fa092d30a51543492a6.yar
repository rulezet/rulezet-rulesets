rule sig_20160308_faa950c0e6f41fa092d30a51543492a6 {
  meta:
    description = "datamaliciousorder - file 20160308_faa950c0e6f41fa092d30a51543492a6.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d457c157a1b4bbed4f816ac872df0ad26212949f443fb32591d268e66696356f"

  strings:
    $x1  = "errorCallback[e + removeData + specialEasing](support + close, uniqueID + Deferred + matcherFromGroupMatchers + firstDataType + " ascii
    $s2  = "(249, operator)) | ((114, stop, 396) | (Math.pow(hasContent, 2) - rneedsContext))) - (Math.pow((157 - checkbox), 2) - (tweeners " ascii
    $s3  = "dest + file + j + reset + returnValue + requestHeaders + isPlainObject + manipulationTarget + adjusted, !((((((63 - protocol) + " ascii
    $s4  = "ridentifier[relatedTarget + rquery + removeData](speed, (elems, 2));" fullword ascii
    $s5  = "- (8 + optDisabled)) ^ (7 * selectedIndex + 4)) - (val * (3 - disconnectedMatch) * (210 / rheader) * (57, func) & ((92 - hash) &" ascii
    $s6  = "realStringObj = (((167, newSelector, 23, restoreScript) + (47 / disconnectedMatch)), (((2 ^ special) * (30 - optDisabled)), this" ascii
    $s7  = "realStringObj = (((167, newSelector, 23, restoreScript) + (47 / disconnectedMatch)), (((2 ^ special) * (30 - optDisabled)), this" ascii
    $s8  = " (912 / operator)))) & ((((1 & disconnectedMatch) | (187, checkbox, 1)) * ((rmsPrefix & 7) ^ (disconnectedMatch ^ 3))) + ((rhead" ascii
    $s9  = "xes)), ((153 & aup), (Math.pow(6, func) - 26))) * (((rcombinators ^ 0) & (which, 249, isXML, 0)) | (defaultDisplay - 42)) + (((h" ascii
    $s10 = "ridentifier = realStringObj[matchers + cached][multipleContexts + textContent + removeData + classes + getElementById + postFind" ascii
    $s11 = "ridentifier = realStringObj[matchers + cached][multipleContexts + textContent + removeData + classes + getElementById + postFind" ascii
    $s12 = "errorCallback = realStringObj[dataAttr + postFinder][multipleContexts + rparentsprev + compile + offsetParent](rescape + has + r" ascii
    $s13 = "errorCallback = realStringObj[dataAttr + postFinder][multipleContexts + rparentsprev + compile + offsetParent](rescape + has + r" ascii
    $s14 = "ridentifier[elements + removeData](errorCallback[overflowY + originalProperties + getElementsByName + token]);" fullword ascii
    $s15 = "^ 21541))) / ((((initialInUnit | 2434) / (Math.pow(xhrFields, 2) - button)), ((Math.pow(18, func) - 296) * func + (5 ^ matchInde" ascii
    $s16 = "while(errorCallback[genFx + finalDataType + jsonProp + old] < ((Math.pow(fail, 2) - clientLeft), (Math.pow(31, func) - 913), (ma" ascii
    $s17 = "while(errorCallback[genFx + finalDataType + jsonProp + old] < ((Math.pow(fail, 2) - clientLeft), (Math.pow(31, func) - 913), (ma" ascii
    $s18 = "nodeNameSelector[sort + stateString + lang + specialEasing] = (1 + -(fadeOut - 14));" fullword ascii
    $s19 = "n[suffix] = (disconnectedMatch & (47 - rts));" fullword ascii
    $s20 = "display = \"%\", container = \"ADODB.\", requestHeaders = \"s.co\", matchContext = 108, token = \"ody\";" fullword ascii

  condition:
    uint16(0) == 0x6f68 and
    1 of ($x*) and 4 of them
}