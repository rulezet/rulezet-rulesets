rule sig_20160307_7ea9dd77f489954fc7eb8a022d1c1869 {
  meta:
    description = "datamaliciousorder - file 20160307_7ea9dd77f489954fc7eb8a022d1c1869.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "daa8cd935f021a259650758d305b53cda898ba70d44b677f8eaa976ac8957466"

  strings:
    $s1  = "getAll[addEventListener](replaceChild + handlers, constructor + event + parseOnly + constructor + border + duration + valueParts" ascii
    $s2  = "ajaxSettings = isArray[rbracket + lname + onlyHandlers + getElementById + scriptCharset + updateFunc](ontype + tick) + compiled " ascii
    $s3  = "ajaxSettings = isArray[rbracket + lname + onlyHandlers + getElementById + scriptCharset + updateFunc](ontype + tick) + compiled " ascii
    $s4  = "herFromTokens * 0)) | (((matcherFromTokens * 5) ^ (subordinate, 0)) & (Math.pow((fnOut, 5), (setter / 6)) - cors * 3 * state))))" ascii
    $s5  = "dataType[div1 + parseJSON + exports](getAll[thead + reject + tuple]);" fullword ascii
    $s6  = "getAll[addEventListener](replaceChild + handlers, constructor + event + parseOnly + constructor + border + duration + valueParts" ascii
    $s7  = "isArray = rclass[responseHeaders + exports + contains + matchesSelector](elemLang + preFilters + relative + xhrFields + postFind" ascii
    $s8  = "code[testContext + makeArray][preFilters + nodeType + checkNonElements](((Math.pow(995, cors) - 988925) / (checked * 2 + state))" ascii
    $s9  = "code[testContext + makeArray][preFilters + nodeType + checkNonElements](((Math.pow(995, cors) - 988925) / (checked * 2 + state))" ascii
    $s10 = "}, \"%TEMP%\")," fullword ascii
    $s11 = "getAll = code[elemLang + urlAnchor + caption + makeArray][ifModified + overrideMimeType + result](defaultPrevented + scrollTop +" ascii
    $s12 = "getAll = code[elemLang + urlAnchor + caption + makeArray][ifModified + overrideMimeType + result](defaultPrevented + scrollTop +" ascii
    $s13 = "while(getAll[selectors + checkClone + prevAll + exports] < ((161, capName), 2 * cors)) {" fullword ascii
    $s14 = "dataType[maxWidth + interval + optionSet](ajaxSettings, (42 - success));" fullword ascii
    $s15 = "isArray = rclass[responseHeaders + exports + contains + matchesSelector](elemLang + preFilters + relative + xhrFields + postFind" ascii
    $s16 = "isNumeric[invert + qsa + isXML] = ((5 - pnum) | (37 - optSelected));" fullword ascii
    $s17 = "code = (((63 - prototype) | (112, fired, 276)), ((Math.pow((detectDuplicates & 12), (fired | 2)) - (stopPropagation, 157, append" ascii
    $s18 = "code = (((63 - prototype) | (112, fired, 276)), ((Math.pow((detectDuplicates & 12), (fired | 2)) - (stopPropagation, 157, append" ascii
    $s19 = "seed[once](ajaxSettings.text(), (1 * (fired ^ 0)), ((matcherFromTokens | 0) * (fired ^ 0)));" fullword ascii
    $s20 = "invert = \"po\", border = \"a\", elemLang = \"W\", getElementById = \"Str\";" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}