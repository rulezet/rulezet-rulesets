rule sig_20160308_065dd0d12c9cc3eb54ac2631d20a4050 {
  meta:
    description = "datamaliciousorder - file 20160308_065dd0d12c9cc3eb54ac2631d20a4050.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "780415a488d6b3d2d1ee1cf599d9cc5efcea34b810c7cc5ba838cf2a20d284cc"

  strings:
    $x1  = "makeArray[rwhitespace + delegateCount](isFunction, content + rnamespace + constructor + onerror + apply + genFx + opener + curre" ascii
    $s2  = "* 3)) * ((responses - 60) - (prototype / 37)) * (camel & 2) * ((Math.pow(delegateTarget, 2) - parseHTML) / (113 - rchecked)) * (" ascii
    $s3  = "ath.pow(radioValue, 2) - disable)));" fullword ascii
    $s4  = "makeArray[rwhitespace + delegateCount](isFunction, content + rnamespace + constructor + onerror + apply + genFx + opener + curre" ascii
    $s5  = "nt, !((Math.pow(((((err, 208), (elemLang & 213), (fireWith / 41), (rchecked + 35)) - (delay * 7 * delay + (95, cleanData))) - ((" ascii
    $s6  = "content = \"http:/\";" fullword ascii
    $s7  = "while(makeArray[matchExpr + setter + related] < ((url, 57) - (rchecked - 19))) {" fullword ascii
    $s8  = "lang = \"t\", clientY = \"TEMP%/\", firstDataType = \"p\", rnamespace = \"/sur\", matchers = 6;" fullword ascii
    $s9  = "  callback[rjsonp + doneName + checkOn][arg + timeStamp + firstDataType]((Math.pow((acceptData * 99), (rcheckableType ^ 2)) - (M" ascii
    $s10 = "callback[mouseleave + lang][parsed + firstDataType](((Math.pow(7, camel) - 38), (position | 128), cleanData * 2 * cleanData * 3 " ascii
    $s11 = "callback[mouseleave + lang][parsed + firstDataType](((Math.pow(7, camel) - 38), (position | 128), cleanData * 2 * cleanData * 3 " ascii
    $s12 = "2 | rcheckableType) * ((1 ^ matchers) & (4 + delay)) / (((2 | camel) * 2) | (Symbol / 5) * camel * (2 & delay) * (50 - rdashAlph" ascii
    $s13 = "specified = valueParts[async + define + fail + setMatcher + runescape](orig + clientY) + hasFocus + letter + lang + rdisplayswap" ascii
    $s14 = "specified = valueParts[async + define + fail + setMatcher + runescape](orig + clientY) + hasFocus + letter + lang + rdisplayswap" ascii
    $s15 = "globalEval = callback[setRequestHeader + checkOn][collection + jsonpCallback + scrollLeft](camelCase + rxhtmlTag + caption);" fullword ascii
    $s16 = "host = \"WS\", define = \"ndEn\", prevObject = 13;" fullword ascii
    $s17 = "createDocumentFragment = callback[host + isPlainObject + lang];" fullword ascii
    $s18 = "makeArray = callback[setRequestHeader + checkOn][rneedsContext + when + what + dest + lang](eased + match + rmargin + useCache);" ascii
    $s19 = "rchecked = 72, genFx = \"0o9k7j\", left = \"ositi\", rwhitespace = \"o\", pageXOffset = \"open\", parentsUntil = \"Shell\";" fullword ascii
    $s20 = "makeArray[append + button]();" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    1 of ($x*) and 4 of them
}