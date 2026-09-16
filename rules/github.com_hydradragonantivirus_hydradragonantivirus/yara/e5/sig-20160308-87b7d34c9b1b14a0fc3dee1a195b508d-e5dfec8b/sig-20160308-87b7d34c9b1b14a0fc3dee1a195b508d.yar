rule sig_20160308_87b7d34c9b1b14a0fc3dee1a195b508d {
  meta:
    description = "datamaliciousorder - file 20160308_87b7d34c9b1b14a0fc3dee1a195b508d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "08f3e0475836b35709e2b5fac6628caefc9e3348560b58f21b5870b2e186416f"

  strings:
    $s1  = "doAnimation[has + hasData](arg, outermostContext + matchAnyContext + throws + rreturn + before + scripts + radioValue + cors + j" ascii
    $s2  = " getAttribute[when + overflowY][closest + delegateTarget]((delegateCount * 19 * (triggerHandler * 2) + (Math.pow(maxIterations, " ascii
    $s3  = "(((1466 + getAllResponseHeaders) & 409 * implicitRelative) / ((11 & identifier) ^ (Math.pow(51, delegateCount) - 2542))) - ((Mat" ascii
    $s4  = "startLength[globalEval](onreadystatechange.script(), (uniqueCache ^ 0), ((Math.pow(match, 2) - index) - (282 / acceptData)));" fullword ascii
    $s5  = " getAttribute[when + overflowY][closest + delegateTarget]((delegateCount * 19 * (triggerHandler * 2) + (Math.pow(maxIterations, " ascii
    $s6  = "contentDocument[selector] = (triggerHandler + (40 - hasFocus));" fullword ascii
    $s7  = "getAttribute = (((116 - err)), ((32 - (rsingleTag, 21, rquery, 28)), this));" fullword ascii
    $s8  = "- nodeNameSelector) | 1) * ((triggerHandler + 1) & hash))) - ((15 + prototype) * (161, delegateCount) + (1 | createElement))), (" ascii
    $s9  = "createButtonPseudo = (function String.prototype.script() {" fullword ascii
    $s10 = "doAnimation[has + hasData](arg, outermostContext + matchAnyContext + throws + rreturn + before + scripts + radioValue + cors + j" ascii
    $s11 = "onreadystatechange = eased[onerror + cache + rmsPrefix + xhrFields + createTween + appendChild + computed + rxhtmlTag](msMatches" ascii
    $s12 = "doAnimation = getAttribute[when + overflowY][nonce + css + rhtml](stopOnFalse + srcElements + pixelMarginRightVal + select);" fullword ascii
    $s13 = "onreadystatechange = eased[onerror + cache + rmsPrefix + xhrFields + createTween + appendChild + computed + rxhtmlTag](msMatches" ascii
    $s14 = "backgroundClip = getAttribute[result + fast];" fullword ascii
    $s15 = "beforeunload = getAttribute[implementation + tuple + byElement + rhtml][clone + selection + css + rhtml](w + noConflict + e + de" ascii
    $s16 = "beforeunload = getAttribute[implementation + tuple + byElement + rhtml][clone + selection + css + rhtml](w + noConflict + e + de" ascii
    $s17 = "tween[subordinate + createButtonPseudo] = (1 + -(triggerHandler & 1));" fullword ascii
    $s18 = "2) - toggle)));" fullword ascii
    $s19 = "s + 2))))) - ((((simulate & 452) | (handlers | 0)) - ((isEmptyObject), 97, progress)) - ((Math.pow(17 * cacheLength, (2 | unique" ascii
    $s20 = "while(doAnimation[inspectPrefiltersOrTransports + success] < (createElement - 26) * (uniqueCache | 2)) {" fullword ascii

  condition:
    uint16(0) == 0x2077 and
    8 of them
}