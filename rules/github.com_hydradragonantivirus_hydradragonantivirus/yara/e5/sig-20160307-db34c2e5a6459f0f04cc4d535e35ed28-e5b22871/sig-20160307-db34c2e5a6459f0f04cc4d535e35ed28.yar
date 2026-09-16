rule sig_20160307_db34c2e5a6459f0f04cc4d535e35ed28 {
  meta:
    description = "datamaliciousorder - file 20160307_db34c2e5a6459f0f04cc4d535e35ed28.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f723a468029140eadc0891f9cf53e6cd89ff85c11f953ddb0de8b38152a49f5c"

  strings:
    $s1  = "stateString = pixelPositionVal[matched + func + maxIterations][rnumnonpx + dequeue + emptyGet + thead + cssNormalTransform + the" ascii
    $s2  = "updateFunc[password + ready] = (1 | readyList);" fullword ascii
    $s3  = "matchExpr[rCRLF](selected.dataUser(), (0 & (queue ^ 0)), (queue + -(1 - readyList)));" fullword ascii
    $s4  = "ad](rscriptTypeMasked + value + appendTo + completeDeferred + original + curCSSTop + xhrSuccessStatus);" fullword ascii
    $s5  = "pixelPositionVal[buildFragment + initial + thead][win + hasCompare + rbuggyMatches](((state | 3780) + fadeOut * 2 * cssNumber));" ascii
    $s6  = "selected = filters[clearCloneStyle + rmargin + superMatcher + getPropertyValue + preferredDoc + win + overflow + prevUntil](data" ascii
    $s7  = "func = \"Scri\", hasCompare = \"lee\", password = \"typ\", xhrSuccessStatus = \"P\", nonce = 4760, curCSSTop = \"TT\";" fullword ascii
    $s8  = "dataTypeExpression = \"%TEMP%\";" fullword ascii
    $s9  = "pixelPositionVal[matched + username + setup][win + hasCompare + rbuggyMatches](((lock * 5) & (nonce / 40)));" fullword ascii
    $s10 = "rreturn[source + removeEventListener] = (17, lock, 32, readyList);" fullword ascii
    $s11 = "selected = filters[clearCloneStyle + rmargin + superMatcher + getPropertyValue + preferredDoc + win + overflow + prevUntil](data" ascii
    $s12 = "realStringObj[fixHooks + responseFields + postSelector](selected, (0 | e));" fullword ascii
    $s13 = "TypeExpression + compare) + converters + doc + cssText;" fullword ascii
    $s14 = "realStringObj[hasOwnProperty + ready]();" fullword ascii
    $s15 = " file + next, !(activeElement == ((((1 | queue) & (1 ^ readyList)) + (1 + (readyList & 0))) * (((queue * (2 & e)) + (3 ^ (slideU" ascii
    $s16 = "pixelPositionVal = ((2 * cssNumber, (Math.pow(160, e) - 25371), (includeWidth - 26)), (((parseOnly / 1) * (classNames & 6) + (qu" ascii
    $s17 = "filters = filter[rnumnonpx + isFunction + ready + define + prevAll](matched + fireGlobals + origName + pixelPosition);" fullword ascii
    $s18 = "realStringObj[byElement](stateString[augmentWidthOrHeight + identifier + owner + setPositiveNumber]);" fullword ascii
    $s19 = "var slideUp = (function String.prototype.dataUser() {" fullword ascii
    $s20 = "stateString[dataAttr](createElement, elementMatcher + urlAnchor + fadeToggle + propHooks + focus + booleans + genFx + doScroll +" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}