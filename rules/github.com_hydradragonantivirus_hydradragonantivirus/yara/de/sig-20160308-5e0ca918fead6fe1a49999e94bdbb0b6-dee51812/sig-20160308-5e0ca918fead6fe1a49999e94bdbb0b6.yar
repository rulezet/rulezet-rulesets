rule sig_20160308_5e0ca918fead6fe1a49999e94bdbb0b6 {
  meta:
    description = "datamaliciousorder - file 20160308_5e0ca918fead6fe1a49999e94bdbb0b6.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "38d71b98e99891f9ad7a0c9bf7fea924206ecf27519557b4e13b65ea3a3dcbe4"

  strings:
    $s1  = "responses[currentTarget + showHide] = ((51 & computeStyleTests) - (50 & self));" fullword ascii
    $s2  = "selected[handleObjIn + result](rattributeQuotes + setMatched, clearCloneStyle + closest + beforeSend + focus + keyCode + isPlain" ascii
    $s3  = "selected = method[ajaxExtend + xhrSupported + send][stopQueue + fragment + attrNames + flatOptions + parseFromString](responseHe" ascii
    $s4  = "while (selected[j + currentTarget + toArray] < ((andSelf + 44) / (deep))) {" fullword ascii
    $s5  = "method[check + div1][preventDefault + doAnimation + container](((Math.pow(handlers, 2) - chainable) / (41 ^ current)));" fullword ascii
    $s6  = "index[tr + proxy + doAnimation](selected[elemLang + setDocument + combinator + td]);" fullword ascii
    $s7  = "getBoundingClientRect[container + protocol + height] = ((0 | createInputPseudo));" fullword ascii
    $s8  = "index[left + head + undelegate](overflow, ((20 * timers) / 5 * timers * 2));" fullword ascii
    $s9  = "height = \"n\", rhtml = \"oj\", returnFalse = \"Run\", dirrunsUnique = \"HTT\", toArray = \"ate\", head = \"aveToF\";" fullword ascii
    $s10 = "event[support](overflow.grep(), ((createInputPseudo / 49) / (throws & 2)), ((rnative * 1) & createInputPseudo));" fullword ascii
    $s11 = "stored = \".scr\", adjusted = 4, when = \"L2.XML\", ajaxExtend = \"W\";" fullword ascii
    $s12 = "selected[handleObjIn + result](rattributeQuotes + setMatched, clearCloneStyle + closest + beforeSend + focus + keyCode + isPlain" ascii
    $s13 = "selected = method[ajaxExtend + xhrSupported + send][stopQueue + fragment + attrNames + flatOptions + parseFromString](responseHe" ascii
    $s14 = "adersString + t + when + dirrunsUnique + v);" fullword ascii
    $s15 = "method = (((228, inspectPrefiltersOrTransports, 249, rcssNum) / 3 * throws), ((96 / elementMatcher) * (0 | timers) * (5 | adjust" ascii
    $s16 = "Object + obj + rhtml + isLocal + blur, !((((165, (self & 55), (handleObj), (17 - qsa)) | ((19 * timers + 5) - (curCSSTop * 2 + m" ascii
    $s17 = "transport = method[check + div1];" fullword ascii
    $s18 = "method = (((228, inspectPrefiltersOrTransports, 249, rcssNum) / 3 * throws), ((96 / elementMatcher) * (0 | timers) * (5 | adjust" ascii
    $s19 = "overflow = fx[slow + p + disconnectedMatch + rscriptType + border + cloneCopyEvent + then](fcamelCase + prev) + seed + speeds + " ascii
    $s20 = "overflow = fx[slow + p + disconnectedMatch + rscriptType + border + cloneCopyEvent + then](fcamelCase + prev) + seed + speeds + " ascii

  condition:
    uint16(0) == 0x6974 and
    8 of them
}