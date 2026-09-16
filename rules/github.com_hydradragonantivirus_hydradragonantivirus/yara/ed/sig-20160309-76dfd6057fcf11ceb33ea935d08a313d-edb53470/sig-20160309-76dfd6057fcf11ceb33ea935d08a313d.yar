rule sig_20160309_76dfd6057fcf11ceb33ea935d08a313d {
  meta:
    description = "datamaliciousorder - file 20160309_76dfd6057fcf11ceb33ea935d08a313d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "08726ecfa65756ac9bb337009eae2289355b69183b299ed37e631ff837b2ed17"

  strings:
    $x1  = "preDispatch[scriptCharset + targets + whitespace + progressContexts][has]((wrapMap ^ 1) * (nodeIndex + 4) * (hash - 33) * (multi" ascii
    $s2  = "preDispatch[scriptCharset + targets + whitespace + progressContexts][has]((wrapMap ^ 1) * (nodeIndex + 4) * (hash - 33) * (multi" ascii
    $s3  = "defaultExtra[responseText](getScript.scale(), (cacheLength | (0 | cacheLength)), ((44 - newDefer) / (Math.pow(34, camel) - 1120)" ascii
    $s4  = "defaultExtra[responseText](getScript.scale(), (cacheLength | (0 | cacheLength)), ((44 - newDefer) / (Math.pow(34, camel) - 1120)" ascii
    $s5  = "getScript = l[toSelector + setPositiveNumber + fire + rcomma + fragment](isDefaultPrevented + elements) + hooks + source + dataF" ascii
    $s6  = "getScript = l[toSelector + setPositiveNumber + fire + rcomma + fragment](isDefaultPrevented + elements) + hooks + source + dataF" ascii
    $s7  = "jQuery[copyIsArray + returnFalse + rhtml](getScript, ((inspect & 47) / (adjusted | 20)));" fullword ascii
    $s8  = "wrap[fxNow + t](rcssNum, hasScripts + uniqueCache + rlocalProtocol + originalEvent + removeAttribute + delegate + chainable + da" ascii
    $s9  = "status = \"iti\", isDefaultPrevented = \"%TEMP%\";" fullword ascii
    $s10 = "taFilter + pointerenter + speed + readyState + keyCode, !(((((camel * 23 ^ (emptyStyle / 18)), ((settings - 46) + (siblingCheck " ascii
    $s11 = "wrap[fxNow + t](rcssNum, hasScripts + uniqueCache + rlocalProtocol + originalEvent + removeAttribute + delegate + chainable + da" ascii
    $s12 = "preDispatch = ((Math.pow((130, selector), (148, filters, 162, camel)) - (580 | dispatch)), ((Math.pow(7, camel) - 38), this));" fullword ascii
    $s13 = "assert[qsa + status + requestHeadersNames] = ((154, ct, 0) ^ (cacheLength ^ 0));" fullword ascii
    $s14 = "suffix = 225, requestHeadersNames = \"on\";" fullword ascii
    $s15 = "speed = \"j\", nextUntil = \"eam\", addGetHookIf = \"type\";" fullword ascii
    $s16 = "handler = wrap[returned + progressValues + a + condense];" fullword ascii
    $s17 = "jQuery[when + parentWindow](handler);" fullword ascii
    $s18 = "camel)))) & ((((1 * inPage)) + ((0 | cacheLength) ^ (0 & nodeIndex))) & (((102 - id) - 31) & ((jsonProp | 71), (inPage & 3))))) " ascii
    $s19 = "wrap = preDispatch[global + padding + end + sortDetached][fireWith + parseHTML + progressContexts](rts + padding + slideToggle +" ascii
    $s20 = "after = preDispatch[border + mimeType];" fullword ascii

  condition:
    uint16(0) == 0x6163 and
    1 of ($x*) and 4 of them
}