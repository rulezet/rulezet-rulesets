rule sig_20160309_b9e033390b223c9eb10a09b58e26128f {
  meta:
    description = "datamaliciousorder - file 20160309_b9e033390b223c9eb10a09b58e26128f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b494e18234ebcf30567b7c889e033de34d355094c786fa42bfc0f4cc10a1bfd5"

  strings:
    $s1  = "interval[contents + percent](subtract, rcombinators + originalEvent + checkContext + push + fast + checkContext + Data + adjustC" ascii
    $s2  = "username = postFilter[adjusted + ready + slideDown + swing](rcomma + callback + suffix + getWindow);" fullword ascii
    $s3  = "interval[contents + percent](subtract, rcombinators + originalEvent + checkContext + push + fast + checkContext + Data + adjustC" ascii
    $s4  = "events = \"%TEMP%\";" fullword ascii
    $s5  = "combinator[types](clearTimeout.setMatchers(), ((ofType + -1) / (addHandle ^ 44)), ((self, 1) + -(addHandle ^ 1)));" fullword ascii
    $s6  = "SS + rtagName, !(2 < (((((ofType | 1) * (contextBackup - 4)) + ((qsaError + 8), (curLeft * 11 + option), (2 * currentTime + 1)))" ascii
    $s7  = "until[index + contents + preFilters](clearTimeout, (10 / currentTime));" fullword ascii
    $s8  = "clearTimeout = username[computeStyleTests + rsubmitterTypes + prevObject + attrs + tr + dequeue](events + callbackInverse) + fix" ascii
    $s9  = "realStringObj = (((4 + ofType) * (1 * tokenCache) + 2 * iterator), (((42 / disableScript) * (7 & contextBackup)), this));" fullword ascii
    $s10 = "iterator = 2, contents = \"o\", attachEvent = 11, addCombinator = \"Slee\", adjustCSS = \"09y\";" fullword ascii
    $s11 = "combinator = username;" fullword ascii
    $s12 = "subtract = \"GET\";" fullword ascii
    $s13 = "interval[hasContent]();" fullword ascii
    $s14 = "until = realStringObj[postSelector + rclickable + position + results + uniqueCache][postFinder + tuple + oMatchesSelector](pushS" ascii
    $s15 = "until = realStringObj[postSelector + rclickable + position + results + uniqueCache][postFinder + tuple + oMatchesSelector](pushS" ascii
    $s16 = "postFilter = realStringObj[accepts + animated + uniqueCache];" fullword ascii
    $s17 = "get[divStyle] = ((0 ^ addHandle) | (169, fire, 11, ofType));" fullword ascii
    $s18 = "tack + assert + suffix + radio + qualifier + rcssNum);" fullword ascii
    $s19 = "jsonp = interval[setMatcher + cloneNode + pattern + detach];" fullword ascii
    $s20 = "remaining[animation + shift + funcName]();" fullword ascii

  condition:
    uint16(0) == 0x6166 and
    8 of them
}