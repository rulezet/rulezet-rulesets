rule sig_20160309_25e1c8d03c2d7066e8b69a460e3ff34b {
  meta:
    description = "datamaliciousorder - file 20160309_25e1c8d03c2d7066e8b69a460e3ff34b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "31a5dc3ad21d600e8433cef89bc6a614c557f87baa6f5ecb877cbe73444c9d78"

  strings:
    $s1  = "createButtonPseudo[string](pageY, offsetHeight + hasFocus + implicitRelative + responses + isSuccess + fragment + sortOrder + to" ascii
    $s2  = " + oldCache + rcombinators + inspect + wrap + getWindow + next + startLength, !((((((Math.pow(preMap, 2) - _default) - (1 * thro" ascii
    $s3  = "expand[amd + response + isArray + whitespace + requestHeaders](returnFalse, ((handle - 11)));" fullword ascii
    $s4  = "returnFalse = finalText[jsonp + binary + doScroll + script + createPositionalPseudo + serializeArray + selectors](pnum + results" ascii
    $s5  = "pageXOffset[getStyles + guid] = ((noGlobal | 5) - (source | 12));" fullword ascii
    $s6  = "returnFalse = finalText[jsonp + binary + doScroll + script + createPositionalPseudo + serializeArray + selectors](pnum + results" ascii
    $s7  = "createButtonPseudo = deepDataAndEvents[addGetHookIf + emptyStyle][rhash + udataCur + after + origName](checkContext + submit + a" ascii
    $s8  = "createButtonPseudo = deepDataAndEvents[addGetHookIf + emptyStyle][rhash + udataCur + after + origName](checkContext + submit + a" ascii
    $s9  = "sortOrder = \"m\", merge = \"Sh\", pnum = \"%TEMP%\", conv = \"wri\", fragment = \"y.co\", statusText = \"rip\";" fullword ascii
    $s10 = "memory[compareDocumentPosition](returnFalse.context(), ((pdataCur - 44) / (_evalUrl | 10)), (checkClone - 1));" fullword ascii
    $s11 = "deepDataAndEvents[$ + statusText + implicitRelative][clearTimeout + getJSON](((conditionFn ^ 111), original * 7, (border + 6171)" ascii
    $s12 = "deepDataAndEvents[$ + statusText + implicitRelative][clearTimeout + getJSON](((conditionFn ^ 111), original * 7, (border + 6171)" ascii
    $s13 = "adown = createButtonPseudo[bindType + curCSSTop + what + siblings];" fullword ascii
    $s14 = "temp = pageXOffset;" fullword ascii
    $s15 = "temp[origType + assert + raw] = (cacheLength | 0);" fullword ascii
    $s16 = "var script = \"ronmen\"," fullword ascii
    $s17 = "deepDataAndEvents = (((2030 & getter) / (266 / box)), ((158, apply, 2), this));" fullword ascii
    $s18 = "getAttribute = expand;" fullword ascii
    $s19 = "getJSON = \"p\", after = \"je\", argument = \"send\";" fullword ascii
    $s20 = "activeElement = \"ML2\", doScroll = \"i\", getter = 2046, documentIsHTML = \"te\";" fullword ascii

  condition:
    uint16(0) == 0x7270 and
    8 of them
}