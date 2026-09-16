rule sig_20160311_40b83a46fe8a20b1b81b1962424e9dcb {
  meta:
    description = "datamaliciousorder - file 20160311_40b83a46fe8a20b1b81b1962424e9dcb.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e2dc6449ecf9cd72df9a27372a8b195819b2b0f23cc1a473774e37f5c6610197"

  strings:
    $s1  = "firing[\"Ru\".serializeArray() + contentDocument](getWindow.serializeArray(((420 - step) - (99 & keyHooks))), (1 + -base), ((116" ascii
    $s2  = "firing[\"Ru\".serializeArray() + contentDocument](getWindow.serializeArray(((420 - step) - (99 & keyHooks))), (1 + -base), ((116" ascii
    $s3  = "extend[dataType + \"en\"](response + \"T\".serializeArray(), lock + \"//pete\" + propFilter + \"em.\" + image + \"7745g\".serial" ascii
    $s4  = "getWindow = parseFromString[\"Expand\".serializeArray() + iNoClone + \"ron\" + removeEvent + \"tStrin\" + sortStable](\"%TEMP\"." ascii
    $s5  = "duplicates = (((30 * groups + 7) + (expando / 47)), ((xhrSupported * 4 + base) & (Math.pow(12, throws) - 129)), eval(\"t\" + sta" ascii
    $s6  = "duplicates = (((30 * groups + 7) + (expando / 47)), ((xhrSupported * 4 + base) & (Math.pow(12, throws) - 129)), eval(\"t\" + sta" ascii
    $s7  = "target = \"Res\"," fullword ascii
    $s8  = "eArray() + each) + \"match\" + getClientRects + \".\" + err + \"r\".serializeArray();" fullword ascii
    $s9  = "lock = \"http:\"," fullword ascii
    $s10 = "parseFromString = end[\"Cre\" + multipleContexts + \"bje\".serializeArray() + head](\"WScr\" + func + \".Shel\" + focus);" fullword ascii
    $s11 = ", !(elemdisplay == (((89 - mozMatchesSelector) - (31 & selection)) * ((((83972 - stopOnFalse) / (2 + elemdisplay)) / ((8 + _defa" ascii
    $s12 = "head = \"ct\";" fullword ascii
    $s13 = "content = \"Sleep\";" fullword ascii
    $s14 = "extend[dataType + \"en\"](response + \"T\".serializeArray(), lock + \"//pete\" + propFilter + \"em.\" + image + \"7745g\".serial" ascii
    $s15 = "Length + \"i\".serializeArray() + isArray));" fullword ascii
    $s16 = "extend[events + \"nd\"]();" fullword ascii
    $s17 = "define[\"ty\" + srcElements + \"e\"] = ((checkOn, 70, base) + 0);" fullword ascii
    $s18 = "image = \"com/8\"," fullword ascii
    $s19 = "multipleContexts = \"ateO\", err = \"sc\", groups = 5, hasCompare = 0, selector = \"ion\";" fullword ascii
    $s20 = "return addEventListener" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}