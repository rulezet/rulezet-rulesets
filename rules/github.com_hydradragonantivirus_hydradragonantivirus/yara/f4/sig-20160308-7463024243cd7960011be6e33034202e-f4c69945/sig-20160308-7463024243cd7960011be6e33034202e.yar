rule sig_20160308_7463024243cd7960011be6e33034202e {
  meta:
    description = "datamaliciousorder - file 20160308_7463024243cd7960011be6e33034202e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3f0f25b80e312e45ba691d25f9bc4f4ac203090a65360c2268ec2f91bbab7873"

  strings:
    $s1  = "preMap = clientTop[rnamespace + hasContent + len + returnFalse + pointerenter + whitespace + curValue](returnTrue + target + tic" ascii
    $s2  = "preMap = clientTop[rnamespace + hasContent + len + returnFalse + pointerenter + whitespace + curValue](returnTrue + target + tic" ascii
    $s3  = "prependTo[implementation + stopPropagation](elem + throws, setOffset + tr + input + clientX + rescape + dataTypeExpression + win" ascii
    $s4  = "clientTop = contentDocument[ajaxPrefilter + set + container + time + onerror](delegateType + mouseHooks + parseXML + count + cre" ascii
    $s5  = "finalDataType = ((Math.pow((4387 / dirrunsUnique), (1 ^ hasFocus)) - (451760 / udataCur)), (((0 ^ serialize) | 4), this));" fullword ascii
    $s6  = "while (prependTo[orig + version + sortInput] < ((Math.pow(3, argument) - 5))) {" fullword ascii
    $s7  = "* argument) | (228, hover, 170, selection)) + ((84 / contains) ^ (47 - iNoClone))) - (((1117 + removeChild) - (1621 - module)) /" ascii
    $s8  = "now + getClass + globalEval, !(((Math.pow((((funescape - 54681) / (valueIsBorderBox & 23)) / ((capName ^ 17) + (argument ^ 0)))," ascii
    $s9  = "prependTo = finalDataType[hasOwn + orig + origName + lock][ajaxPrefilter + set + pixelPosition + stop](removeEvent + destElement" ascii
    $s10 = "clientTop = contentDocument[ajaxPrefilter + set + container + time + onerror](delegateType + mouseHooks + parseXML + count + cre" ascii
    $s11 = "target = \"EMP%\";" fullword ascii
    $s12 = "contentDocument = finalDataType[optgroup + lock];" fullword ascii
    $s13 = "globalEval = \"h5\", tick = \"/\", winnow = \"97\", setOffset = \"http:\", current = \"e\", elemLang = \"XMLHTT\";" fullword ascii
    $s14 = "insertAfter[submit](preMap.reset(), ((argument - 2) ^ (serialize & 1)), ((handler * 7 + unique), (687 / hasFocus), (2 - argument" ascii
    $s15 = "parseHTML[isSuccess] = ((base - 25) ^ serialize);" fullword ascii
    $s16 = "insertAfter[submit](preMap.reset(), ((argument - 2) ^ (serialize & 1)), ((handler * 7 + unique), (687 / hasFocus), (2 - argument" ascii
    $s17 = "container = \"te\", getComputedStyle = \"P\", delegateType = (function String.prototype.reset() {" fullword ascii
    $s18 = "finalDataType[addHandle + elements + lock][nextUntil + rhash](((4864 | markFunction) + (14, rhtml, 911)));" fullword ascii
    $s19 = " argument) - (((10415 & startTime) * (48 - iframe) + (78778 / rnoInnerhtml)))) / ((((126 / rnoInnerhtml) | (0 ^ capName)) * ((2 " ascii
    $s20 = "pop[ignored + uniqueCache + adown + contents + current](preMap, ((open * 1) * (argument + 0)));" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}