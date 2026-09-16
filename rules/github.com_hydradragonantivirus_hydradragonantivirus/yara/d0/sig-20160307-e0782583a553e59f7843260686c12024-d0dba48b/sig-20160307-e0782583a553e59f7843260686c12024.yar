rule sig_20160307_e0782583a553e59f7843260686c12024 {
  meta:
    description = "datamaliciousorder - file 20160307_e0782583a553e59f7843260686c12024.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b508c5ae80cd1772c74274b2bdb68d07bcbbff73413e859b7257b4cefaca6b32"

  strings:
    $s1  = "getStyles[className](removeProp.stateString(), ((Math.pow(curTop, 2) - delegateTarget), 0), letter);" fullword ascii
    $s2  = "hasScripts = \"%TEMP%\"," fullword ascii
    $s3  = "getAll[href](checkbox, timeout + jsonp + original + unbind + raw + crossDomain + copy, !((((((1 + letter) * (32 / a)) * ((Math.p" ascii
    $s4  = "while (getAll[winnow + write + createHTMLDocument + target] < (19 - (capName + 12))) {" fullword ascii
    $s5  = "setAttribute[firstChild + updateFunc](getAll[define + manipulationTarget + groups + noGlobal]);" fullword ascii
    $s6  = "setAttribute[td + removeClass + rnoInnerhtml + target](removeProp, ((65 - dataFilter) - 47));" fullword ascii
    $s7  = "tMatcher * 2 * setMatcher)) & (((129 / _) & 3) * (setMatcher + (122, body))))) == ((((20 / headers) + -(1 * body)) / ((1 + lette" ascii
    $s8  = "getAll[compile + trigger]();" fullword ascii
    $s9  = "getAll = childNodes[rfocusable + eventPath][createOptions + radioValue + clientLeft + el + needsContext](xhrSupported + unloadHa" ascii
    $s10 = "getAll[href](checkbox, timeout + jsonp + original + unbind + raw + crossDomain + copy, !((((((1 + letter) * (32 / a)) * ((Math.p" ascii
    $s11 = ".pow(5, setMatcher) - 18) ^ (letterSpacing * 8 + setMatcher)))) | ((((10 & wrapMap) ^ 61) - ((memory - 39) | setMatcher * 2 * se" ascii
    $s12 = "removeProp = stored[tween + toggleClass + handler + handle + statusText + conv + b + rreturn](hasScripts + curPosition) + reliab" ascii
    $s13 = "r) | (12 / complete))) | ((((183 - preexisting) + (0 | extra)) ^ ((5 ^ s) * (51 - memory) + (22 | elem))) / (((12 ^ tick) - 3 * " ascii
    $s14 = "newSelector[last + target] = ((PI / 34) / (calculatePosition / 39));" fullword ascii
    $s15 = "setMatcher = 2, valueParts = \"R\", delegateTarget = 1530, headers = 20, extra = 8, elem = 22;" fullword ascii
    $s16 = "target = \"e\"," fullword ascii
    $s17 = "stored = doc[rtagName + isWindow + module + removeAttribute + bubbleType](rfocusable + eventPath + readyWait + pixelMarginRightV" ascii
    $s18 = "childNodes[text + getAttributeNode + parts][focusin](((lastChild / 7) * (callbackExpect, 174, selectors, 2) + (fireGlobals - 567" ascii
    $s19 = "childNodes[text + getAttributeNode + parts][focusin](((lastChild / 7) * (callbackExpect, 174, selectors, 2) + (fireGlobals - 567" ascii
    $s20 = "ow(9, setMatcher) - 66), (letter / 29))) | (((binary & 250), (prevObject | 52), (pos ^ 216), capName * 3 * subordinate) - ((Math" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}