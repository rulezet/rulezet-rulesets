rule sig_20160309_8850afb88dfc3be8132ffee15b0c72a8 {
  meta:
    description = "datamaliciousorder - file 20160309_8850afb88dfc3be8132ffee15b0c72a8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "dc1feadd2effe60a251ddf054fc7dd5324d17e9c3b7ebb9134f52e5c60282368"

  strings:
    $s1  = "getAttributeNode = eventHandle[bySet + triggered][not + getJSON + result + makeArray + elemLang](contents + innerText + operator" ascii
    $s2  = "getAttributeNode = eventHandle[bySet + triggered][not + getJSON + result + makeArray + elemLang](contents + innerText + operator" ascii
    $s3  = "reject[funcName + fadeTo](getAll, startLength + chainable + dirruns + rsubmitterTypes + hasData + l + booleans, !(7 == (((((uniq" ascii
    $s4  = "eventHandle[createTween + resolveValues][getElementsByTagName + properties + list](((1967 ^ rscriptTypeMasked)));" fullword ascii
    $s5  = "ueID & 183), (head / 13)) & ((subtract & 1) | source)) - ((3 * bp * 19 * bp & (76 | hasFocus)), ((1 * subtract) * (2 + _$)))) + " ascii
    $s6  = "reject[funcName + fadeTo](getAll, startLength + chainable + dirruns + rsubmitterTypes + hasData + l + booleans, !(7 == (((((uniq" ascii
    $s7  = "reject = eventHandle[rpseudo + input + progress][async + support + before](postDispatch + doScroll + window + conditionFn);" fullword ascii
    $s8  = "extend = \"and\", rscriptTypeMasked = 15671, checkClone = \"Fi\", ajaxHandleResponses = \"pt.She\", arr = \"Respon\", preDispatc" ascii
    $s9  = "matcherFromGroupMatchers = toSelector[not + rheaders + getBoundingClientRect + before](button + ajaxHandleResponses + old);" fullword ascii
    $s10 = "getAttributeNode[siblings + list + preventDefault]();" fullword ascii
    $s11 = "extend = \"and\", rscriptTypeMasked = 15671, checkClone = \"Fi\", ajaxHandleResponses = \"pt.She\", arr = \"Respon\", preDispatc" ascii
    $s12 = "eventHandle = (((4 | handleObj) + (127 & fn)), (((1 * subtract) * (44 - pointerleave)), this));" fullword ascii
    $s13 = "matchedCount[hasOwnProperty](xhrFields.initialInUnit(), 0, (subtract + -1));" fullword ascii
    $s14 = "(Math.pow((((Math.pow(13, bp) - 150) + (bp ^ 11)), ((isXML ^ 36) + (scale + 93)), (bp * 13 * bp, (0 | uid), (62 + resolveWith))," ascii
    $s15 = ", parts, 4)), ((subtract * 0) | (truncate - 5))) - source * (125 / addHandle))))));" fullword ascii
    $s16 = " ((Math.pow(120, bp) - 14272) / (opener & 36))), (((subtract + -1) ^ (_$ | 0)) ^ bp)) - (Math.pow(((1 ^ escapedWhitespace) + (23" ascii
    $s17 = "operator = \"DB\";" fullword ascii
    $s18 = "pointerleave = 42, implementation = 27, fadeTo = \"n\", preferredDoc = \"send\", getElementsByTagName = \"Sl\", bp = 2;" fullword ascii
    $s19 = "uniqueID = 255, isArrayLike = \"clos\", rpseudo = \"W\", doScroll = \"ML2.\", contents = \"A\";" fullword ascii
    $s20 = "getAttributeNode[globalEventContext + checkClone + collection](xhrFields, (1 ^ escapedWhitespace));" fullword ascii

  condition:
    uint16(0) == 0x7369 and
    8 of them
}