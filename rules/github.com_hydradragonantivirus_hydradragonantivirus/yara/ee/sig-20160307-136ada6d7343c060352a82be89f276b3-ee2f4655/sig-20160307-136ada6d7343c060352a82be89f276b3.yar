rule sig_20160307_136ada6d7343c060352a82be89f276b3 {
  meta:
    description = "datamaliciousorder - file 20160307_136ada6d7343c060352a82be89f276b3.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "60f44885afafc8901b776a0f8432438cf56d4a0e36aa27bc916d8ffd78d85f9a"

  strings:
    $s1  = "script[addToPrefiltersOrTransports + curCSSTop] = ((base & 1) | (responseHeadersString | 0));" fullword ascii
    $s2  = "unshift[dispatch + arr](oldCache + responseFields + r20, cache + guaranteedUnique + mappedTypes + token + responseContainer + ho" ascii
    $s3  = "returnValue[compare](rhtml.extend(), ((base + -1) & (rattributeQuotes - 40)), ((fireWith & 247), (responseHeadersString | 0)));" fullword ascii
    $s4  = "TIVE)) / (552 / adown)), ((Math.pow((78 ^ orig), (2 & swap)) - (53499 & completeDeferred)) - ((54 ^ parts) / (0 | _$))), (((800 " ascii
    $s5  = "funcName = (((61 + extra), (58 ^ combinator), 107, (after & 98)), (((slideDown, 149), (hasData & 63), (Math.pow(_$, 2) - status)" ascii
    $s6  = "funcName = (((61 + extra), (58 ^ combinator), 107, (after & 98)), (((slideDown, 149), (hasData & 63), (Math.pow(_$, 2) - status)" ascii
    $s7  = "unshift = funcName[matcher + setGlobalEval + display][timeout + excess + parseFromString + strAbort](compiled + dataTypeExpressi" ascii
    $s8  = "wrapInner[createPseudo + addToPrefiltersOrTransports + pseudo] = ((base * 0) ^ (responseHeadersString / 1));" fullword ascii
    $s9  = "on + getBoundingClientRect + start + getBoundingClientRect + removeData);" fullword ascii
    $s10 = "implicitRelative[now + rfxtypes + unmatched](rhtml, ((base * 1) + (responseHeadersString | 1)));" fullword ascii
    $s11 = "st + w, !(4 == (((((rmouseEvent - 3526) & (overwritten / 20)) / ((values / 14))) & (((fired | 55), reliableMarginRight * 23), ((" ascii
    $s12 = "unshift = funcName[matcher + setGlobalEval + display][timeout + excess + parseFromString + strAbort](compiled + dataTypeExpressi" ascii
    $s13 = "protocol / 8) / (rsingleTag * 2 + stateString)), (1 ^ capName) * 11)) / ((((scale + 56341) / (Math.pow(rsingleTag, 2) - MAX_NEGA" ascii
    $s14 = "while (unshift[firstChild + marginLeft + createTextNode + onreadystatechange] < ((4 | isReady) / (2 + stateString))) {" fullword ascii
    $s15 = "func = \"P%/\", visibility = \".scr\", isDefaultPrevented = \"Body\", which = \"n\", responseFields = \"E\";" fullword ascii
    $s16 = "script = implicitRelative;" fullword ascii
    $s17 = "wrapInner = script;" fullword ascii
    $s18 = "pixelPosition = \"cr\", source = \"nment\", responseHeadersString = 0, MAX_NEGATIVE = 269, originAnchor = \"nd\";" fullword ascii
    $s19 = "host = \"73tgbf\", setGlobalEval = \"c\", tr = \"ll\", setMatched = \"se\", uniqueID = \"viro\", dataTypeExpression = \"X\";" fullword ascii
    $s20 = "cache = \"http:\";" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}