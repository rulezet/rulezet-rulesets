rule sig_20160308_45b69ef448de41bd19b3bdf7a75bc386 {
  meta:
    description = "datamaliciousorder - file 20160308_45b69ef448de41bd19b3bdf7a75bc386.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "00dfe5d159bf0f64c5b055ae615878d8b68ad9857dd316b0378479a016b4e1d0"

  strings:
    $s1  = "classCache[parseOnly](top + notify, marginRight + newSelector + event + setMatcher + lname + text + timers + toSelector + parent" ascii
    $s2  = ", !(rkeyEvent == ((((3, risSimple, 51, left) - (35 | simple)), (3 * document * 5, (valHooks | 24), (Math.pow(rsingleTag, 2) - ge" ascii
    $s3  = "isDefaultPrevented[rscriptType + valueIsBorderBox + password](shift, 2);" fullword ascii
    $s4  = "click[nodeType + preFilter][initial + col](((20 ^ jsonProp), (Math.pow(163, contains) - 26369), contains * 2 * contains * 3 * co" ascii
    $s5  = "unqueued[cache](shift.scriptCharset(), ((document + 14) - (round - 51)), (parents + -1));" fullword ascii
    $s6  = "stopPropagation[col + optionSet + xhrSupported + getter] = ((0 ^ matcherIn) ^ (0 / originalOptions));" fullword ascii
    $s7  = "addEventListener = handle[parentWindow + getAttributeNode + overflowX + response](reset + aup + unshift + register);" fullword ascii
    $s8  = "tAttribute)), ((85 & param) ^ (47 ^ removeEvent)), (Math.pow((39 ^ on), 2) - (Math.pow(duration, 2) - beforeSend))) / (((Math.po" ascii
    $s9  = "click = (((Math.pow(7, contains) - 40) | (createPositionalPseudo - 105)), ((contains | 0) * (contains & 2) * (contains & 3) * (p" ascii
    $s10 = "click = (((Math.pow(7, contains) - 40) | (createPositionalPseudo - 105)), ((contains | 0) * (contains & 2) * (contains & 3) * (p" ascii
    $s11 = "defaultValue = \"%TEMP%\";" fullword ascii
    $s12 = "click[nodeType + preFilter][initial + col](((20 ^ jsonProp), (Math.pow(163, contains) - 26369), contains * 2 * contains * 3 * co" ascii
    $s13 = "jsonProp = 58, ofType = (function String.prototype.scriptCharset() {" fullword ascii
    $s14 = "isDefaultPrevented[unit + getter]();" fullword ascii
    $s15 = "password = \"le\";" fullword ascii
    $s16 = "while (classCache[copy + fxNow + mapped + funcName] < ((boolHook - 103) / (map * 7 + keyCode))) {" fullword ascii
    $s17 = "script = \"nd\";" fullword ascii
    $s18 = "optionSet = \"osit\", round = 68, rscriptType = \"saveTo\";" fullword ascii
    $s19 = "classCache[html + script]();" fullword ascii
    $s20 = "cache = nodeValue + getter;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}