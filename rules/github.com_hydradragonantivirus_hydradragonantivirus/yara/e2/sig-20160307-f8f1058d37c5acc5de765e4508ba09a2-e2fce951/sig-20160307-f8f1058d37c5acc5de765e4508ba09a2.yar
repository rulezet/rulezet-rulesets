rule sig_20160307_f8f1058d37c5acc5de765e4508ba09a2 {
  meta:
    description = "datamaliciousorder - file 20160307_f8f1058d37c5acc5de765e4508ba09a2.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "bac7add825ca1ee3851d47e20addd5518edf0e5a982e5bc3fa81f996c53215a7"

  strings:
    $s1  = "progress[list](div, click + timer + tag + set + expanded + event + rsibling + ready + PI, !(2 < ((((submit * 8 + getBoundingClie" ascii
    $s2  = "ntRect) & 3 * valueIsBorderBox * 3 * getBoundingClientRect) - (1 * submit) * (2 * getBoundingClientRect + 1)) * (((Math.pow(bool" ascii
    $s3  = "(Math.pow((postDispatch ^ 14), (related / 33)) - getBoundingClientRect * 3 * getBoundingClientRect * 17 * valueIsBorderBox)) | (" ascii
    $s4  = "while (progress[e + orig + text] < ((Math.pow(getBoundingClientRect, 2) - step) & (4 & htmlPrefilter))) {" fullword ascii
    $s5  = "progress = on[rneedsContext + setAttribute + siblings][gotoEnd + getWindow + unit + overwritten](clientTop + arr + delegateCount" ascii
    $s6  = "on[module + cssExpand + configurable][onerror](((setMatcher + 4148) - (prefilterOrFactory * 2 + sortStable)));" fullword ascii
    $s7  = "prev[rheaders](access.slideUp(), ((35 - file) | 0), (postMap + -1));" fullword ascii
    $s8  = "progress[list](div, click + timer + tag + set + expanded + event + rsibling + ready + PI, !(2 < ((((submit * 8 + getBoundingClie" ascii
    $s9  = "defaultDisplay = matchExpr[removeAttribute + clone + contains + ifModified + elem](getComputedStyle + rsingleTag + unloadHandler" ascii
    $s10 = "defaultDisplay = matchExpr[removeAttribute + clone + contains + ifModified + elem](getComputedStyle + rsingleTag + unloadHandler" ascii
    $s11 = "access = defaultDisplay[requestHeaders + until + root + adjusted + options + support + pageXOffset](jsonpCallback + p) + getResp" ascii
    $s12 = "access = defaultDisplay[requestHeaders + until + root + adjusted + options + support + pageXOffset](jsonpCallback + p) + getResp" ascii
    $s13 = "on = ((13410 / (col * 5 + lastChild)), ((Math.pow((2 | step), (1 * valueIsBorderBox)) - (43, firstElementChild, 212, flag)), thi" ascii
    $s14 = "on = ((13410 / (col * 5 + lastChild)), ((Math.pow((2 | step), (1 * valueIsBorderBox)) - (43, firstElementChild, 212, flag)), thi" ascii
    $s15 = "progress = on[rneedsContext + setAttribute + siblings][gotoEnd + getWindow + unit + overwritten](clientTop + arr + delegateCount" ascii
    $s16 = "unit = \"Obj\", tag = \"www\", support = \"Str\", keepScripts = \"TP\", rsingleTag = \"Script\", setMatcher = 17829;" fullword ascii
    $s17 = "ngClientRect & 3) + (one - 55)) / ((step | 112) - (oMatchesSelector ^ 99)))));" fullword ascii
    $s18 = "eans, 2) - fixHooks) & 34) - ((box + 0) ^ (dataTypes - 27)))) * ((((disabled * 3 + statusCode) - (11 * valueIsBorderBox + 2)) - " ascii
    $s19 = "domManip[ignored + ajax](access, ((24 - xhrFields)));" fullword ascii
    $s20 = "domManip = on[elemdisplay + rdisplayswap + configurable][removeAttribute + pseudo + siblings + ifModified + pageX + doneName + f" ascii

  condition:
    uint16(0) == 0x6e75 and
    8 of them
}