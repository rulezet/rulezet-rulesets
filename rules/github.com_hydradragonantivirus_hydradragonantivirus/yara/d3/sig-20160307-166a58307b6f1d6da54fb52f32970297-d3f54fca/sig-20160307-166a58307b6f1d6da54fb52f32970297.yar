rule sig_20160307_166a58307b6f1d6da54fb52f32970297 {
  meta:
    description = "datamaliciousorder - file 20160307_166a58307b6f1d6da54fb52f32970297.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9b7d119566821d92d23aee854ba9f7b97ce3fb89868a51d53c22e46c2beb647a"

  strings:
    $s1  = "startLength = prefix[rcomma + processData + stopPropagation][tokenize + handle + setFilters + handle + onload + stopPropagation]" ascii
    $s2  = "startLength = prefix[rcomma + processData + stopPropagation][tokenize + handle + setFilters + handle + onload + stopPropagation]" ascii
    $s3  = "base[tuples](createOptions + createFxNow, getAllResponseHeaders + sortOrder + parent + not + tmp + onerror + getJSON + jsonProp " ascii
    $s4  = "prefix[operator + prevAll + stopPropagation][addBack]((Math.pow(90, (querySelectorAll / 25)) - checkNonElements * 2 * returned *" ascii
    $s5  = "prefix[operator + prevAll + stopPropagation][addBack]((Math.pow(90, (querySelectorAll / 25)) - checkNonElements * 2 * returned *" ascii
    $s6  = "base = prefix[globalEval + value + v][tokenize + text + getWindow](stopQueue + queue + propFilter + addToPrefiltersOrTransports " ascii
    $s7  = "base = prefix[globalEval + value + v][tokenize + text + getWindow](stopQueue + queue + propFilter + addToPrefiltersOrTransports " ascii
    $s8  = "base[tuples](createOptions + createFxNow, getAllResponseHeaders + sortOrder + parent + not + tmp + onerror + getJSON + jsonProp " ascii
    $s9  = "newSelector = \"n\", show = 13, getAllResponseHeaders = \"http:\";" fullword ascii
    $s10 = "not = \"udio\", last = \"en\", v = \"pt\", onerror = \"a.com.\", tuples = \"open\", selection = \"Scr\";" fullword ascii
    $s11 = "ready = prefix[operator + selection + refElements];" fullword ascii
    $s12 = "checkContext = 73, percent = \"h\", processData = \"p\";" fullword ascii
    $s13 = "prefilterOrFactory = \"%TEMP%\";" fullword ascii
    $s14 = "while(base[dequeue + define] < (Math.pow(lname, (0 | checkNonElements)) - (121, isEmptyObject, 129, returned))) {" fullword ascii
    $s15 = "temp = \"Run\";" fullword ascii
    $s16 = "(locked + fontWeight + thead);" fullword ascii
    $s17 = "startLength[postFinder + createButtonPseudo + handle]();" fullword ascii
    $s18 = "camelCase = ready[defaultExtra + ifModified + bulk](operator + code + originalEvent + clientX + code + percent + method);" fullword ascii
    $s19 = "onlyHandlers[attachEvent + createButtonPseudo + ajaxSetup + newSelector] = (1 + -(show - 12));" fullword ascii
    $s20 = "siblingCheck = temp;" fullword ascii

  condition:
    uint16(0) == 0x6e6f and
    8 of them
}