rule sig_20160308_f53c0404292d50a2c705f4d2b6106d34 {
  meta:
    description = "datamaliciousorder - file 20160308_f53c0404292d50a2c705f4d2b6106d34.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c402120e33f58d6b5f84ea3aa082072665a7591c51f648ae7a390b7412ab803e"

  strings:
    $x1  = "visibility[sortInput](checkClone, display + n + num + lock + constructor + preferredDoc + pixelPositionVal + contentType + first" ascii
    $s2  = ", !((((((2, temp, 66, seed) & (32 | fn)) - ((3370 & currentTarget) / (24 + e))) - (Math.pow((Math.pow((1 + cached), (1 + progres" ascii
    $s3  = "computed[firing + which + getClass][subtract + innerText]((Math.pow(41 * remove, 2) - (rnoContent, 23, needsContext)));" fullword ascii
    $s4  = "computed[responseHeadersString + iterator + getClass][matchesSelector + conv2](((Math.pow(4769, remove) - 22738115) + (prependTo" ascii
    $s5  = "computed[responseHeadersString + iterator + getClass][matchesSelector + conv2](((Math.pow(4769, remove) - 22738115) + (prependTo" ascii
    $s6  = "matcherIn = computed[hasFocus + rwhitespace + getClass][getComputedStyle + rdisplayswap + curOffset + targets](cssNormalTransfor" ascii
    $s7  = "computed = (((105 + remove) - (2940 / submit)), ((134, createTextNode, 78, getElementsByClassName), this));" fullword ascii
    $s8  = "visibility = computed[text + getClass][preFilter + tokenCache + _load](nextAll + condense + returnFalse);" fullword ascii
    $s9  = "w = \"oFile\", soFar = 44, parseXML = \"write\", targets = \"ject\";" fullword ascii
    $s10 = "result = optgroup[nidselect + timers + safeActiveElement + siblings + all + pushStack + matchesSelector + func + elementMatcher]" ascii
    $s11 = "(readyWait + testContext + preferredDoc) + fx + fail + random + rsubmitterTypes + inPage + modified + isArrayLike;" fullword ascii
    $s12 = "visibility[sortInput](checkClone, display + n + num + lock + constructor + preferredDoc + pixelPositionVal + contentType + first" ascii
    $s13 = "while(visibility[emptyGet + getElementsByTagName + elemdisplay + delegateCount] < (remove * (1 * remove))) {" fullword ascii
    $s14 = "optgroup = allTypes[preFilter + uniqueID + multipleContexts](responseHeadersString + contexts + rcomma + inPage + map + concat);" ascii
    $s15 = "replaceChild[curCSSTop + doScroll + matchAnyContext + sortOrder] = ((soFar, 1) * (cssHooks - 37));" fullword ascii
    $s16 = "contentType = \"k7j\", round = \"c\", returnFalse = \"LHTTP\";" fullword ascii
    $s17 = "display = \"http:/\", responseHeadersString = \"WSc\";" fullword ascii
    $s18 = "s)) - (500 * remove + 185)), ((base / 33) - (fxNow & 63))) - (stopPropagation)))) == 4));" fullword ascii
    $s19 = "temp = 6;" fullword ascii
    $s20 = "allTypes = computed[hasFocus + current];" fullword ascii

  condition:
    uint16(0) == 0x6966 and
    1 of ($x*) and 4 of them
}