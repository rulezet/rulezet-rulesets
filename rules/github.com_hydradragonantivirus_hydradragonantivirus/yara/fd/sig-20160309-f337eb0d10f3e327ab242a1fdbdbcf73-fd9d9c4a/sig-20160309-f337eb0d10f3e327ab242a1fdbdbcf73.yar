rule sig_20160309_f337eb0d10f3e327ab242a1fdbdbcf73 {
  meta:
    description = "datamaliciousorder - file 20160309_f337eb0d10f3e327ab242a1fdbdbcf73.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3161bc1b83de40ec1d5408ee6bbf1f019b6d484a4b9b606608ef749032da7dc6"

  strings:
    $s1  = ")) / ((((56 + elementMatchers) & (4191 / ap)), ((2 + when) * 3)) & (((properties / 9) + (rhash - 8)) | (Math.pow((Math.pow(leadi" ascii
    $s2  = "fixInput[compiled](method.uniqueID(), ((namespaces - 43) / (leadingRelative & 4)), ((createTextNode, 121, ready) | (0 ^ ready)))" ascii
    $s3  = "fixInput[compiled](method.uniqueID(), ((namespaces - 43) / (leadingRelative & 4)), ((createTextNode, 121, ready) | (0 ^ ready)))" ascii
    $s4  = "prevObject[swing](newSelector + left, unmatched + adown + selector + map + protocol + newDefer + stopQueue + jsonp + remaining +" ascii
    $s5  = "e)) + ((18 | name) - (75 - statusCode))) & (((Math.pow(978, when) - 954734) / (onload - 70)) | (delegateCount ^ (17 & isXMLDoc))" ascii
    $s6  = "prevAll[andSelf + handlers][fn + originAnchor](((Math.pow(10644, when) - 113279736)));" fullword ascii
    $s7  = " cache + keyHooks + maxIterations, !(((((xhrSuccessStatus * (1 + when)) * (Math.pow((3 & xhrSuccessStatus), 2) - (leadingRelativ" ascii
    $s8  = "method = notify[createHTMLDocument + getResponseHeader + checked + offsetWidth + rejectWith + props + prev + newUnmatched + buil" ascii
    $s9  = "reset[tr + reliableMarginLeftVal] = ((1 + -i) ^ 1);" fullword ascii
    $s10 = "ngRelative, 2) - body), (0 | when)) - (3 * parts + 2))))) == name));" fullword ascii
    $s11 = "prevAll = (((16 + ready) | (167, eventPath)), (((2 ^ ready) * (115, properties, 8)), this));" fullword ascii
    $s12 = "dataFilter[elementMatcher + cssFn] = ((nodeType / 17), ready);" fullword ascii
    $s13 = "container[map + hover + funcName + preFilter](method, ((0 | when) ^ (0 | ready)));" fullword ascii
    $s14 = "method = notify[createHTMLDocument + getResponseHeader + checked + offsetWidth + rejectWith + props + prev + newUnmatched + buil" ascii
    $s15 = "newSelector = \"G\", originAnchor = \"ep\", pixelPosition = \"onseB\", matches = \".Shell\", selected = \"write\";" fullword ascii
    $s16 = "notify = showHide[options + lock + file + rbrace](suffix + rfxtypes + matches);" fullword ascii
    $s17 = "prevObject[swing](newSelector + left, unmatched + adown + selector + map + protocol + newDefer + stopQueue + jsonp + remaining +" ascii
    $s18 = "container[createPseudo + prev]();" fullword ascii
    $s19 = "ready = 0," fullword ascii
    $s20 = "var body = 9," fullword ascii

  condition:
    uint16(0) == 0x6f70 and
    8 of them
}