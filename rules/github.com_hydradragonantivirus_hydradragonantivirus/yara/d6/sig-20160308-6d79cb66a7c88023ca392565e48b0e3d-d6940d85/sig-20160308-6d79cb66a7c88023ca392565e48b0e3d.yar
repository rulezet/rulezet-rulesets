rule sig_20160308_6d79cb66a7c88023ca392565e48b0e3d {
  meta:
    description = "datamaliciousorder - file 20160308_6d79cb66a7c88023ca392565e48b0e3d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "cb3486d3d74038e9729941e689c5e9b2e150d1dff195ae7dcfd2af1d982dc1dc"

  strings:
    $s1  = "using[createInputPseudo + nodeValue + safeActiveElement][disabled](((Math.pow(inspectPrefiltersOrTransports, 2) - getScript), (1" ascii
    $s2  = "using[createInputPseudo + nodeValue + safeActiveElement][disabled](((Math.pow(inspectPrefiltersOrTransports, 2) - getScript), (1" ascii
    $s3  = "params[script](now, urlAnchor + rpseudo + then + rrun + fn + setMatched + toArray + buildFragment + marginRight, !(((((definePro" ascii
    $s4  = "sortDetached[capName + propHooks + createComment](parent, ((matcherFromTokens + 35), (Math.pow(dataTypes, 2) - rkeyEvent), (3520" ascii
    $s5  = "sortDetached[capName + propHooks + createComment](parent, ((matcherFromTokens + 35), (Math.pow(dataTypes, 2) - rkeyEvent), (3520" ascii
    $s6  = "mentation), (38 - leadingRelative)) - (260581 & node)) / (Math.pow(2 * fadeOut * 7, (fadeOut ^ 0)) - (setRequestHeader & 1021)))" ascii
    $s7  = " - (Math.pow(((responseType / 7), (Math.pow(host, 2) - rmargin)), ((1 * ajaxHandleResponses) | 2)) - ((el & 494)))) ^ ((((leadin" ascii
    $s8  = "sortDetached[end](params[srcElements + nodeType + responseHeadersString + finish + ready]);" fullword ascii
    $s9  = "while(params[matchAnyContext + finish + oldCache + getPropertyValue] < ((Math.pow(3, fadeOut) - 5) & (slideUp - 31))) {" fullword ascii
    $s10 = "params = using[createInputPseudo + pdataOld][getElementsByClassName + notify + tokens + rootjQuery](firstDataType + relative + b" ascii
    $s11 = "params = using[createInputPseudo + pdataOld][getElementsByClassName + notify + tokens + rootjQuery](firstDataType + relative + b" ascii
    $s12 = "parentOffset = \"nd\", tokens = \"bje\", value = \".scr\";" fullword ascii
    $s13 = "perty * 1) ^ ((cache - 8) / (tag & 22))) + (((fadeOut + 3) & (disableScript, 5)) - ((implicitRelative * 3 + createPseudo), 29 * " ascii
    $s14 = "params[script](now, urlAnchor + rpseudo + then + rrun + fn + setMatched + toArray + buildFragment + marginRight, !(((((definePro" ascii
    $s15 = "parent = orig[remaining + parentOffset + isDefaultPrevented + pos + propName + contains + operator](dequeue + origName) + append" ascii
    $s16 = "parent = orig[remaining + parentOffset + isDefaultPrevented + pos + propName + contains + operator](dequeue + origName) + append" ascii
    $s17 = "stopPropagation[setup](parent.idx(), ((rbuggyMatches - 33)), (cache - 8));" fullword ascii
    $s18 = "orig = fxNow[parentsUntil + childNodes + open](createInputPseudo + copyIsArray + removeEventListener);" fullword ascii
    $s19 = "script = \"open\";" fullword ascii
    $s20 = "sortDetached[script]();" fullword ascii

  condition:
    uint16(0) == 0x6173 and
    8 of them
}