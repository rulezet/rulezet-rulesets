rule sig_20160307_89dea807d4b8845a245344e22615ec98 {
  meta:
    description = "datamaliciousorder - file 20160307_89dea807d4b8845a245344e22615ec98.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "63788e068d7a31c41fa13c0a8bb792239bbdf0e3acb09bb1932cc3e34b642a1e"

  strings:
    $s1  = "addEventListener[r20 + parentOffset](completeDeferred, fadeIn + msMatchesSelector + unmatched + stored + propFix + content + sub" ascii
    $s2  = "s = attrHandle[preventDefault + selected + startTime + src + sort + outermost + delegateType](postFilter + rscriptTypeMasked + o" ascii
    $s3  = "s = attrHandle[preventDefault + selected + startTime + src + sort + outermost + delegateType](postFilter + rscriptTypeMasked + o" ascii
    $s4  = "addEventListener[r20 + parentOffset](completeDeferred, fadeIn + msMatchesSelector + unmatched + stored + propFix + content + sub" ascii
    $s5  = "dequeue[delegateType + targets + cssProps + converters](s, ((1 + values) & (0 | always)));" fullword ascii
    $s6  = "s), (239 - (lock * 2 + dir))), (((13 ^ fireWith) - (12 & contents)) * ((57 / fadeTo) | (0 ^ assert)) + 3 * (assert & 2)), (asser" ascii
    $s7  = " assert + 12))) - ((values * 2) * (values ^ 3) * (callbackContext ^ 2) * (assert ^ 0) * (combinator / 19) / ((contents - 4) | (v" ascii
    $s8  = "while (addEventListener[copy + handle + children + converters] < ((contents + 130) / (unshift & 62))) {" fullword ascii
    $s9  = "dequeue = rtagName[expanded + getStyles + prevObject][done + args + prevObject](elementMatchers + ignored + pos + dirruns);" fullword ascii
    $s10 = "addEventListener = rtagName[reverse + prevObject][multipleContexts + attributes + animated + converters + argument + check](padd" ascii
    $s11 = "dequeue[click](addEventListener[grep + createComment + namespaces + specialEasing]);" fullword ascii
    $s12 = "tract + originalOptions + el + parseHTML, !(((((17 * always * (26 - lock) + (3 * event + 1)), ((col - 135) - assert * 11 * alway" ascii
    $s13 = " / implicitRelative), (2 | assert)) * ((38 - unshift) & (235, currentTime, 21, always)) * (0 | assert) * (54 / expand) / ((2 * d" ascii
    $s14 = "rtagName = (((155 + attr) - (2904 / lock)), (((5 + values) & (119 / percent)), this));" fullword ascii
    $s15 = "t & (2 + callbackContext)), (Math.pow(((30 - resolveValues) ^ (6 + off)), (2 | (values * 0))) - ((Math.pow(preFilter, 2) - handl" ascii
    $s16 = "er) ^ (24 + removeAttribute)))) - ((((5 * tag) + (308 / originAnchor)) + (Math.pow((159, select), (2 + callbackContext)) - (20 *" ascii
    $s17 = "addEventListener = rtagName[reverse + prevObject][multipleContexts + attributes + animated + converters + argument + check](padd" ascii
    $s18 = "rbrace[exports](s.docElem(), (3 * pseudo, (1 & callbackContext)), ((1 + callbackContext) + -(1 & values)));" fullword ascii
    $s19 = "content = \"t/9\";" fullword ascii
    $s20 = "contentType[success + timeoutTimer + MAX_NEGATIVE] = ((callbackContext) / (0 ^ trigger));" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}