rule sig_20160308_5faa2382ade6f5f58a1d9a954d40a04e {
  meta:
    description = "datamaliciousorder - file 20160308_5faa2382ade6f5f58a1d9a954d40a04e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a43702558f480d936cc25181230cbeb1164e32e8701dd4e43665313e7135a80d"

  strings:
    $s1  = "webkitMatchesSelector[speed](hasOwnProperty, truncate + dataAndEvents + wait + crossDomain + complete + until + active + curCSS " ascii
    $s2  = "(dirrunsUnique & 1) * (subordinate / 16)), ((dirrunsUnique & 0) | (currentTarget + 0))) - ((delegateTarget & 63) - (tmp & 63))) " ascii
    $s3  = "* nodeNameSelector + 1)))), ((((dirrunsUnique | 0) * (dirrunsUnique * 3)) ^ (Math.pow(simple * 3 * currentTarget * 7, (currentTa" ascii
    $s4  = "rget)) - 3923 * currentTarget * 2)), (((Math.pow(seed, 2) - isArray) & (29 * assert + 18)) + (Math.pow((nodes / 9), (dirrunsUniq" ascii
    $s5  = "  teardown[reverse + bp][matcherFromTokens + hookFn](((addEventListener | 0) | (Math.pow(getWindow, 2) - parentNode)));" fullword ascii
    $s6  = "ue * 2)) - (Math.pow(blur, 2) - PI))), (Math.pow(22, currentTarget) - 455), ((rclickable - 53) / (simple + 13)))) - ((Math.pow((" ascii
    $s7  = "Fields), (1960 / genFx), (298 - rtrim), 2))) - ((currentTarget * 3 * simple + (1 & addEventListener)) | ((800 / clientTop) & (2 " ascii
    $s8  = "isImmediatePropagationStopped = value[tokens + noConflict + stopQueue + filter + dataShow + content](event + rtypenamespace + ge" ascii
    $s9  = "teardown[code + support][serialize]((Math.pow((9422 & caption), (0 | currentTarget)) - (92261676 & checkContext)));" fullword ascii
    $s10 = "+ (((transport & 155) - (Math.pow(converters, 2) - classNames)) - (43 * currentTarget - (1295 / genFx))))) == 8));" fullword ascii
    $s11 = "detach[manipulationTarget + hasCompare](isImmediatePropagationStopped, ((38 / holdReady) + (0 | dirrunsUnique)));" fullword ascii
    $s12 = "& replaceChild)) & ((1 & dirrunsUnique) + (4 | addEventListener))), (((1 * addEventListener) & (34 / ontype)) ^ ((281 - response" ascii
    $s13 = "isImmediatePropagationStopped = value[tokens + noConflict + stopQueue + filter + dataShow + content](event + rtypenamespace + ge" ascii
    $s14 = "webkitMatchesSelector = teardown[nodeType + firstChild + support][fixHooks + empty + rnative + overflow + identifier](click + tr" ascii
    $s15 = "webkitMatchesSelector = teardown[nodeType + firstChild + support][fixHooks + empty + rnative + overflow + identifier](click + tr" ascii
    $s16 = "tBoundingClientRect) + clientX + orig + disabled + exports;" fullword ascii
    $s17 = "detach = teardown[code + support][copyIsArray + parentWindow + JSON + dataTypeExpression + pageXOffset](random + rnoInnerhtml + " ascii
    $s18 = "while(webkitMatchesSelector[parseHTML + gotoEnd + setOffset] < ((assert & 7) & (dirrunsUnique ^ 7))) {" fullword ascii
    $s19 = "detach = teardown[code + support][copyIsArray + parentWindow + JSON + dataTypeExpression + pageXOffset](random + rnoInnerhtml + " ascii
    $s20 = "webkitMatchesSelector[speed](hasOwnProperty, truncate + dataAndEvents + wait + crossDomain + complete + until + active + curCSS " ascii

  condition:
    uint16(0) == 0x6170 and
    8 of them
}