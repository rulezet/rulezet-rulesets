rule sig_20160308_8bc926a14121180c9a115cc35e4e8088 {
  meta:
    description = "datamaliciousorder - file 20160308_8bc926a14121180c9a115cc35e4e8088.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8a95ff385e3d2dfdb9c7c668afe7b6b30aa7a073438467f1ba6f98447d641ad2"

  strings:
    $s1  = "origCount[rdashAlpha](tweeners, getResponseHeader + matchers + detach + runescape + overwritten + cssFn + fire + holdReady + get" ascii
    $s2  = "es), (38 * needsContext + 14), (Math.pow(version, 2) - fontWeight), (2 + mouseenter))) - ((321842 & getAllResponseHeaders) / 3 *" ascii
    $s3  = "atOptions & 27)), ((mouseenter | 0) | (emptyGet / 17))) - ((key + 15) + mouseenter)) - ((2 * needsContext * 3 | (trigger * 3)) &" ascii
    $s4  = " 44) + (hold | 0)) / (needsContext * 17 * locked * 2, (getStyles - 24), (adown * 2 + compile), (16 + postSelector))) - (((1 * of" ascii
    $s5  = "defaultView = ((3 * locked * 3 * locked * 3 - (getAttributeNode / 26)), (((offsetHeight ^ 9) + (locked + 0)), this));" fullword ascii
    $s6  = "origCount = defaultView[compare + cssPrefixes + xml][firstDataType + func + num](load + progressValues + find + responseHeaders " ascii
    $s7  = "origCount = defaultView[compare + cssPrefixes + xml][firstDataType + func + num](load + progressValues + find + responseHeaders " ascii
    $s8  = "dataShow[rrun](blur.nodeNameSelector(), ((1 & context) + -(0 | context)), 0);" fullword ascii
    $s9  = "defaultView[sortInput + fadeIn][which + siblings]((Math.pow((Math.pow(10383, needsContext) - 107794467), needsContext) - (128558" ascii
    $s10 = "))) & ((context * (48 - win)) | ((52 - offsetWidth) ^ (0 & context)))) * ((Math.pow(((Math.pow(124, needsContext) - 15250) / (fl" ascii
    $s11 = "el = \"%TEMP%\"," fullword ascii
    $s12 = "defaultView[sortInput + fadeIn][which + siblings]((Math.pow((Math.pow(10383, needsContext) - 107794467), needsContext) - (128558" ascii
    $s13 = "ElementsByClassName, !((((Math.pow(((trigger * 6) * (needsContext * 2) + (Math.pow(empty, 2) - version)), ((250 & rattributeQuot" ascii
    $s14 = "inPage = defaultView[operator + subordinate + returned];" fullword ascii
    $s15 = "blur = clearCloneStyle[prefix + requestHeadersNames + elemLang + originalEvent + implicitRelative + insertAfter](el + flag) + rp" ascii
    $s16 = "defaultView[operator + xml][async + rmouseEvent](((suffix ^ 50) * needsContext + (242 / parentNode)));" fullword ascii
    $s17 = "blur = clearCloneStyle[prefix + requestHeadersNames + elemLang + originalEvent + implicitRelative + insertAfter](el + flag) + rp" ascii
    $s18 = "one[once + offset + grep] = ((132 - t) - (308 / onlyHandlers));" fullword ascii
    $s19 = " locked * 3)) / (((ownerDocument * 2 + doAnimation) & (524 | isArray)) / ((6 * locked + 1) ^ (sortDetached | 36)))) - ((((tick -" ascii
    $s20 = "origCount[rdashAlpha](tweeners, getResponseHeader + matchers + detach + runescape + overwritten + cssFn + fire + holdReady + get" ascii

  condition:
    uint16(0) == 0x6f6e and
    8 of them
}