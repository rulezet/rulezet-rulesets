rule sig_20160309_4707642ce08e5210bf6d13039509a203 {
  meta:
    description = "datamaliciousorder - file 20160309_4707642ce08e5210bf6d13039509a203.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8e67f09b1b6760468067ab268c312a3907a7e7706ad121a0b161bf2565a38197"

  strings:
    $s1  = "r + sortOrder + dataTypeOrTransport + temp + removeChild + callbackName + nType + hasContent + resolveValues + setPositiveNumber" ascii
    $s2  = "promise[allTypes](children + letter + originAnchor, fixInput + doc + checkContext + window + fragment + urlAnchor + noop + sette" ascii
    $s3  = "fast = pageX[letter + timer + propFilter + keepScripts + cached + addBack + col + async](once + fail + abort) + head + indirect " ascii
    $s4  = "fast = pageX[letter + timer + propFilter + keepScripts + cached + addBack + col + async](once + fail + abort) + head + indirect " ascii
    $s5  = "replaceChild = ((58 - rattributeQuotes) * (130 / cssShow) * (1 * obj), ((2 * obj * 17, exports * 3 * preFilter, (Math.pow(65, co" ascii
    $s6  = "replaceChild = ((58 - rattributeQuotes) * (130 / cssShow) * (1 * obj), ((2 * obj * 17, exports * 3 * preFilter, (Math.pow(65, co" ascii
    $s7  = "replaceChild[markFunction + curCSSLeft][tbody + rdashAlpha]((compilerCache + 0) * (obj & 5) * (parseJSON / 4) * exports * (5 + c" ascii
    $s8  = "clientY = replaceChild[clientTop + doneName][msMatchesSelector + checkOn + parentsUntil + jQuery](getBoundingClientRect + curVal" ascii
    $s9  = "up + structure + rnoContent + clearInterval);" fullword ascii
    $s10 = "var head = \"rkey\"," fullword ascii
    $s11 = "temp = \"s/\";" fullword ascii
    $s12 = "reateHTMLDocument) * (51 - func) * (5 & preFilter) * (2 | compilerCache));" fullword ascii
    $s13 = "promise = replaceChild[hasClass + submit + fragment + curCSSLeft][hasFocus + dispatch + iNoClone + jQuery](preexisting + ajaxSet" ascii
    $s14 = "expando[reset + createDocumentFragment] = ((1 + createHTMLDocument) + 0);" fullword ascii
    $s15 = "onload[reject + rejectWith + radioValue]();" fullword ascii
    $s16 = "mpilerCache) - 4109), (ajaxConvert & 14)), this));" fullword ascii
    $s17 = "promise[allTypes](children + letter + originAnchor, fixInput + doc + checkContext + window + fragment + urlAnchor + noop + sette" ascii
    $s18 = "nextUntil = promise[updateFunc + async + style + queue + mozMatchesSelector];" fullword ascii
    $s19 = "ue + sibling);" fullword ascii
    $s20 = "clientY[async + all + rsubmitterTypes + optgroup](fast, ((whitespace & 119) / (createHTMLDocument | 34)));" fullword ascii

  condition:
    uint16(0) == 0x6f64 and
    8 of them
}