rule sig_20160308_8040e266b3b9fff9a2ee6deb9ab81a31 {
  meta:
    description = "datamaliciousorder - file 20160308_8040e266b3b9fff9a2ee6deb9ab81a31.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f6876098cab7273bfad9526ed80a5c0c66bc4f54695eeeb50be05183f79befbb"

  strings:
    $s1  = "bool[inspectPrefiltersOrTransports + newContext](ajaxExtend + set, focusin + writable + matcherFromTokens + time + prefilterOrFa" ascii
    $s2  = "getElementsByName[delegateTarget + excess + holdReady + set + inspectPrefiltersOrTransports + old + defaultDisplay](qsaError, (3" ascii
    $s3  = "getElementsByName[delegateTarget + excess + holdReady + set + inspectPrefiltersOrTransports + old + defaultDisplay](qsaError, (3" ascii
    $s4  = "setMatcher[input + animate + letterSpacing][udataCur](((93, using, 75, rscriptTypeMasked) - (Math.pow(90, rheaders) - 7996)));" fullword ascii
    $s5  = "nts) + (17917 / match))) / (((3 ^ disableScript) / 1) * ((events * 3) + (events ^ 0)) + (Math.pow((events * 5), (parseJSON - 41)" ascii
    $s6  = "setMatcher = (((3940 / tbody) - (14 * charset + 9)), ((Math.pow((charset * 3 + isDefaultPrevented), (0 ^ rheaders)) - (Math.pow(" ascii
    $s7  = "settings = createOptions[rkeyEvent + attachEvent + num + setFilters](input + protocol + pixelMarginRightVal + rhtml + ready + ho" ascii
    $s8  = " bp)) | ((236, keepScripts, 191, getElementsByTagName) ^ (10 ^ deepDataAndEvents))) & (((145 + remove) + (17, hasFocus, 218, pus" ascii
    $s9  = "settings = createOptions[rkeyEvent + attachEvent + num + setFilters](input + protocol + pixelMarginRightVal + rhtml + ready + ho" ascii
    $s10 = "while (bool[r20 + closest + newSelector] < (destElements - 15) * rheaders) {" fullword ascii
    $s11 = "setMatcher[properties + setFilters][each + mouseHooks](((qualifier ^ 12640) - (getElementById * 2 + all)));" fullword ascii
    $s12 = "321, rheaders) - 102700)), this));" fullword ascii
    $s13 = "qsaError = settings[collection + scripts + r20 + PI + selectedIndex + class2type + el](init + computeStyleTests) + isEmptyObject" ascii
    $s14 = "qsaError = settings[collection + scripts + r20 + PI + selectedIndex + class2type + el](init + computeStyleTests) + isEmptyObject" ascii
    $s15 = "getElementsByName[slideDown + docElem + holdReady](bool[wrapMap + sortDetached + getAllResponseHeaders]);" fullword ascii
    $s16 = "bool[inspectPrefiltersOrTransports + newContext](ajaxExtend + set, focusin + writable + matcherFromTokens + time + prefilterOrFa" ascii
    $s17 = "bool = setMatcher[_queueHooks + pipe + setFilters][extra + list + obj + defaultValue](dequeue + protocol + j + find + eq + parse" ascii
    $s18 = "container[abort](qsaError.overflow(), ((0 / resolveValues) & 0), ((events & 1) * (keys, 16, box, 0)));" fullword ascii
    $s19 = "bool = setMatcher[_queueHooks + pipe + setFilters][extra + list + obj + defaultValue](dequeue + protocol + j + find + eq + parse" ascii
    $s20 = "getElementsByName = setMatcher[properties + setFilters][node + fire + propFilter](cos + obj + percent + firingIndex + parseXML);" ascii

  condition:
    uint16(0) == 0x7570 and
    8 of them
}