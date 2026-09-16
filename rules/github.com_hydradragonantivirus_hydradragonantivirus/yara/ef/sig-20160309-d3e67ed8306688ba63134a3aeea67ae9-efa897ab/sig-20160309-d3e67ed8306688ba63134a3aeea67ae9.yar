rule sig_20160309_d3e67ed8306688ba63134a3aeea67ae9 {
  meta:
    description = "datamaliciousorder - file 20160309_d3e67ed8306688ba63134a3aeea67ae9.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "86ad34a55015f9dc6f652766e9685edf460f6f807529121bd71f5538c29f33f8"

  strings:
    $s1  = "backgroundClip[propFix + propFilter + rbuggyMatches](pseudo, ready + removeProp + fixHook + letter + winnow + complete + thead +" ascii
    $s2  = "cssHooks[temp + rsingleTag + etag][compare + pageXOffset + hasContent + firstDataType]((bySet - 1) * (index, 206, defer) * 2 * (" ascii
    $s3  = "cssHooks[temp + rsingleTag + etag][compare + pageXOffset + hasContent + firstDataType]((bySet - 1) * (index, 206, defer) * 2 * (" ascii
    $s4  = "_jQuery = matchedCount[errorCallback + bind + initialInUnit + nextUntil + targets + createPositionalPseudo + multipleContexts](t" ascii
    $s5  = "cssHooks = (((9 * obj + 2) - (Math.pow(params, 2) - content)), (((0 | responseType) & (1 * responseType)), this));" fullword ascii
    $s6  = "_jQuery = matchedCount[errorCallback + bind + initialInUnit + nextUntil + targets + createPositionalPseudo + multipleContexts](t" ascii
    $s7  = "backgroundClip[propFix + propFilter + rbuggyMatches](pseudo, ready + removeProp + fixHook + letter + winnow + complete + thead +" ascii
    $s8  = "Math.pow(18, nextAll) - 296))) + ((defaultPrefilter | (0 / hidden)) ^ ((1 * responseType) + (0 ^ defaultPrefilter))))) == 10));" fullword ascii
    $s9  = "lastModified[curLeft + identifier + curCSS + unshift + hasContent](_jQuery, ((1 * defer) & 2));" fullword ascii
    $s10 = "position[dirruns](_jQuery.defaultView(), ((32 - index)), ((7 - bySet) + -(1 + defaultPrefilter)));" fullword ascii
    $s11 = "backgroundClip = cssHooks[temp + xhrFields][isXML + createFxNow + combinator + copyIsArray + etag](superMatcher + compare + disp" ascii
    $s12 = "lastModified = cssHooks[pixelMarginRight + image + xhrFields][letterSpacing + hasContent + height + random](excess + isHidden + " ascii
    $s13 = "lastModified = cssHooks[pixelMarginRight + image + xhrFields][letterSpacing + hasContent + height + random](excess + isHidden + " ascii
    $s14 = "backgroundClip[expanded + hasContent + radioValue]();" fullword ascii
    $s15 = "& 15))) * (((xhrSuccessStatus / 26) * (content / 4)) | ((ontype | 0) | (responseType * 5))) * (((responseType | 41), (responseTy" ascii
    $s16 = "tAll ^ 1) & defer) & ((88 - has) - (28 + defaultPrefilter))) * (((13702 & iNoClone) / (8 | xhrSuccessStatus)) / ((0 ^ defer) ^ (" ascii
    $s17 = "lastModified[ajaxSettings + hasCompare](structure);" fullword ascii
    $s18 = "backgroundClip = cssHooks[temp + xhrFields][isXML + createFxNow + combinator + copyIsArray + etag](superMatcher + compare + disp" ascii
    $s19 = "speed = \".scr\";" fullword ascii
    $s20 = "dirruns = handler + j;" fullword ascii

  condition:
    uint16(0) == 0x6168 and
    8 of them
}