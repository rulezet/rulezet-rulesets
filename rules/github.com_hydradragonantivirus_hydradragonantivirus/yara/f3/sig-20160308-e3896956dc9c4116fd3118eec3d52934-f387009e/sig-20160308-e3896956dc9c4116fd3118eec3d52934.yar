rule sig_20160308_e3896956dc9c4116fd3118eec3d52934 {
  meta:
    description = "datamaliciousorder - file 20160308_e3896956dc9c4116fd3118eec3d52934.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d6c34ae0c707b2e8338bb914583a0bf0a6ff75ef01836363b9b48781a194dd8e"

  strings:
    $s1  = "while (contentDocument[targets + after + _jQuery] < (Math.pow((msg * 3), (pseudo - 18)) - name)) {" fullword ascii
    $s2  = "contentDocument[rootjQuery](matched, createPositionalPseudo + rdisplayswap + setPositiveNumber + attrHandle + checkOn + reset + " ascii
    $s3  = "contentDocument = conditionFn[readyList + wrapMap + pixelMarginRight][show + getStyles + hasContent](until + assert + urlAnchor " ascii
    $s4  = "contentDocument = conditionFn[readyList + wrapMap + pixelMarginRight][show + getStyles + hasContent](until + assert + urlAnchor " ascii
    $s5  = "a = \"Obj\", m = \"sen\", targets = \"ready\", dirruns = \"leep\", support = 26;" fullword ascii
    $s6  = "conditionFn[parentWindow + addEventListener + pixelMarginRight][scriptCharset + dirruns](((107 & setFilters), (4590 / getClass)," ascii
    $s7  = " * first + 6), (Math.pow(writable, 2) - selectedIndex), (21 ^ getWindow))), (Math.pow(((14640 / getClass) / (12 & adown)), (0 | " ascii
    $s8  = "contentDocument[rootjQuery](matched, createPositionalPseudo + rdisplayswap + setPositiveNumber + attrHandle + checkOn + reset + " ascii
    $s9  = "text | 2))) ^ (Math.pow(hookFn, 2) - first) * ((0 | currentValue)))) > 1));" fullword ascii
    $s10 = "attaches[each](stopPropagation.cssProps(), ((Math.pow(172, currentValue) - 29380), (amd ^ 1), (rsubmittable ^ 1), (cssPrefixes -" ascii
    $s11 = "attaches[each](stopPropagation.cssProps(), ((Math.pow(172, currentValue) - 29380), (amd ^ 1), (rsubmittable ^ 1), (cssPrefixes -" ascii
    $s12 = "conditionFn = (((200 | inspect) & (63 ^ display)), ((Math.pow((2 * currentValue), (2 & tfoot)) - (15 & Deferred)), this));" fullword ascii
    $s13 = "(currentValue + 0))) - ((disable, 181), (whitespace + 4), (clearQueue / 37), (Math.pow(defer, 2) - fast))), ((2 | tfoot) * (50 /" ascii
    $s14 = "lock[rxhtmlTag](contentDocument[augmentWidthOrHeight + condense + preDispatch + r20]);" fullword ascii
    $s15 = "lock[replaceWith + xhrSupported]();" fullword ascii
    $s16 = "unbind = conditionFn[xhrSuccessStatus + pixelMarginRight];" fullword ascii
    $s17 = "lock[all + dirrunsUnique]();" fullword ascii
    $s18 = "   conditionFn[checked + original + attachEvent][window + curCSS](((2678 / support) - (1 * tfoot)));" fullword ascii
    $s19 = "documentIsHTML = \".scr\", classes = \"Run\", all = \"o\";" fullword ascii
    $s20 = "getWindow = 127, w = \"ndEn\", after = \"sta\", display = 133, original = \"p\", condense = \"po\";" fullword ascii

  condition:
    uint16(0) == 0x6564 and
    8 of them
}