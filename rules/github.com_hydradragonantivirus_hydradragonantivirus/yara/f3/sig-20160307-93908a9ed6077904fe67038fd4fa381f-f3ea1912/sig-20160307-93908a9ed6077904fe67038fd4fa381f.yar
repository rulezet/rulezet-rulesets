rule sig_20160307_93908a9ed6077904fe67038fd4fa381f {
  meta:
    description = "datamaliciousorder - file 20160307_93908a9ed6077904fe67038fd4fa381f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3675e9e796b1f092ee749d65c92967fa29476e14715f6354276703957b210574"

  strings:
    $s1  = "contents[tbody + slideDown + rnative][propName + isXMLDoc]((Math.pow((63 & ofType), (215, postDispatch)) - (Math.pow(2440, postD" ascii
    $s2  = "contents[tbody + slideDown + rnative][propName + isXMLDoc]((Math.pow((63 & ofType), (215, postDispatch)) - (Math.pow(2440, postD" ascii
    $s3  = "trigger[prefix](charset, postSelector + defaultExtra + relatedTarget + augmentWidthOrHeight + params + rcomma + stateString + lo" ascii
    $s4  = "trigger[prefix](charset, postSelector + defaultExtra + relatedTarget + augmentWidthOrHeight + params + rcomma + stateString + lo" ascii
    $s5  = "contents = (((3377 + view) / (7 * postDispatch + 4)), (((subordinate | 161) / (binary + 6)), this));" fullword ascii
    $s6  = " + fail + relatedTarget) + genFx + sibling + list;" fullword ascii
    $s7  = "relatedTarget = \"/\", padding = \"sa\", options = \"hell\", list = \".scr\", boxSizingReliableVal = 5;" fullword ascii
    $s8  = "while (trigger[firing + pointerleave] < ((binary - 13) | (Math.pow(scrollTop, 2) - boxSizingReliableVal))) {" fullword ascii
    $s9  = "get = always[Expr + defaultPrefilter + preFilters + elements + escaped + buildFragment + head + reliableMarginLeft](fail + rhtml" ascii
    $s10 = "contents[collection + linear][rnumnonpx + augmentWidthOrHeight + select](((setOffset ^ 8635) & (contentType - 10310)));" fullword ascii
    $s11 = "maxIterations[rbrace](get.keys(), (subordinate & 1), ((subordinate ^ 0) & (doAnimation * 1)));" fullword ascii
    $s12 = "rattributeQuotes[padding + createPseudo + rcomma + test](get, ((doAnimation ^ 0) * (postDispatch & 2)));" fullword ascii
    $s13 = "trigger = contents[tbody + slideDown + rnative][replaceChild + attrHandle + rreturn + attrHandle](setter + expanded + version + " ascii
    $s14 = "trigger = contents[tbody + slideDown + rnative][replaceChild + attrHandle + rreturn + attrHandle](setter + expanded + version + " ascii
    $s15 = "nidselect[reset] = ((Math.pow(reverse, 2) - html), (45 + related), 1);" fullword ascii
    $s16 = "rattributeQuotes = contents[tbody + getBoundingClientRect + response][DOMParser + s + rreturn + attrHandle](qsa + callbackContex" ascii
    $s17 = "rattributeQuotes = contents[tbody + getBoundingClientRect + response][DOMParser + s + rreturn + attrHandle](qsa + callbackContex" ascii
    $s18 = "always = text[parseXML + setRequestHeader + anim](showHide + attributes + options);" fullword ascii
    $s19 = "text = contents[showHide + response];" fullword ascii
    $s20 = "getBoundingClientRect = (function Object.prototype.keys() {" fullword ascii

  condition:
    uint16(0) == 0x6572 and
    8 of them
}