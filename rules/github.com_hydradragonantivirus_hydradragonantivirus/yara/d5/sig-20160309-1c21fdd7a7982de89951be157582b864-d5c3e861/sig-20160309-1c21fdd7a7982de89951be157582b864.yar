rule sig_20160309_1c21fdd7a7982de89951be157582b864 {
  meta:
    description = "datamaliciousorder - file 20160309_1c21fdd7a7982de89951be157582b864.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9eb779a68629f3d2d169cc9fcadbc662b2824cd625be0bb7b4a11e8563c40108"

  strings:
    $s1  = "elementMatcher[dataType](matcherFromTokens, getElementById + push + uniqueSort + hasScripts + rtrim + oMatchesSelector + pop + p" ascii
    $s2  = "hooks = insertBefore[fragment + fixInput + requestHeaders](eq + getScript + proxy + i);" fullword ascii
    $s3  = "elementMatcher[dataType](matcherFromTokens, getElementById + push + uniqueSort + hasScripts + rtrim + oMatchesSelector + pop + p" ascii
    $s4  = "3, id) - 4)) & ((restoreScript, 51, show) | 73 * id)), (((5364 / timeStamp) | (122 ^ timeout)) / (5 | _jQuery) * (Math.pow(3, id" ascii
    $s5  = "charCode = hooks[unshift + getElementsByClassName + conv + computed + maxIterations + rcssNum + sortOrder](testContext + raw + n" ascii
    $s6  = "ame) + clientTop + jsonp + events + content + identifier + flatOptions + parents + getClass;" fullword ascii
    $s7  = "elementMatcher = argument[udataCur + responseFields + size][tweeners + postDispatch + exports + PI + margin](modified + l + modi" ascii
    $s8  = "elementMatcher = argument[udataCur + responseFields + size][tweeners + postDispatch + exports + PI + margin](modified + l + modi" ascii
    $s9  = "timeout = 6009, namespaces = \"pe\", content = \"xt\", restoreScript = 249, timeStamp = 9, pseudo = \"B.St\";" fullword ascii
    $s10 = "argument = (((93 ^ first) - (138, addEventListener)), ((48 - copy) * (2 + needsContext), this));" fullword ascii
    $s11 = ", 47)) & (((result & 447) / id * 2 * id) / ((33 / valHooks) + (Math.pow(33, id) - 1053))))) == optDisabled));" fullword ascii
    $s12 = ") - 4)), (((globalEval & 15) / (Math.pow(_jQuery, 2) - valHooks)) & (96 / checkDisplay))) + (((63 & curOffset) / ((163 & parent)" ascii
    $s13 = "argument[deep + size][noGlobal](2 * (id + 3) * (_jQuery | 5) * (boxSizingReliable - 46) * responseHeaders * (2 + uniqueCache) * " ascii
    $s14 = "argument[deep + size][noGlobal](2 * (id + 3) * (_jQuery | 5) * (boxSizingReliable - 46) * responseHeaders * (2 + uniqueCache) * " ascii
    $s15 = "document = elementMatcher[hash + toggleClass + postDispatch + unit];" fullword ascii
    $s16 = "unshift = \"E\", append = 163, preferredDoc = \"ope\", Expr = \"ToFile\", matcherFromTokens = \"GET\";" fullword ascii
    $s17 = "responseHeaders = 3, rbracket = \"TP\", fixInput = \"ateObj\", hash = \"Re\", rinputs = 8;" fullword ascii
    $s18 = "elementMatcher[pipe]();" fullword ascii
    $s19 = "var pipe = \"send\"," fullword ascii
    $s20 = "name = \"P%/\", postSelector = \"close\", uniqueSort = \"ih\", pageY = \"S\";" fullword ascii

  condition:
    uint16(0) == 0x6475 and
    8 of them
}