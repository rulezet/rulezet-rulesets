rule sig_20160309_108499563144bc0b41a7f44ba91e0e68 {
  meta:
    description = "datamaliciousorder - file 20160309_108499563144bc0b41a7f44ba91e0e68.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f187354e7b93d432008c61c86306aad49834a995f2be4710a28a86abe29b83d3"

  strings:
    $s1  = "clientLeft[module + completeDeferred](callbackName + params, event + preferredDoc + compilerCache + oldCache + promise + globalE" ascii
    $s2  = "ventContext + style + host + fadeTo + collection, !((((((transports - 28) / (using ^ 50)) + (Math.pow(MAX_NEGATIVE * 2, (value -" ascii
    $s3  = "seekingTransport[setMatched + parentOffset] = ((orig | 32) / (Math.pow(version, 2) - matchesSelector));" fullword ascii
    $s4  = "clientLeft = focusin[resolveValues + target][jsonp + pseudo + compareDocumentPosition + compiled + wrapAll + raw](callback + res" ascii
    $s5  = "headers = \"%TEMP%\";" fullword ascii
    $s6  = "to[constructor + processData]();" fullword ascii
    $s7  = " + orig) ^ (3 & disconnectedMatch)))), ((((1 + slideToggle) + -1) | (Math.pow((dirruns / 29), (active & 2)) - (tbody & 19645))) " ascii
    $s8  = "to[get + matchIndexes + speed + div1](optionSet, ((8 - preFilters) * (68, responses, 173, disconnectedMatch)));" fullword ascii
    $s9  = "clientLeft = focusin[resolveValues + target][jsonp + pseudo + compareDocumentPosition + compiled + wrapAll + raw](callback + res" ascii
    $s10 = "getPropertyValue[matcherFromTokens + input]();" fullword ascii
    $s11 = "var target = \"ipt\"," fullword ascii
    $s12 = "optionSet = special[onload + clearCloneStyle + stopImmediatePropagation + globalEval + pageXOffset + radioValue](headers + dataA" ascii
    $s13 = "optionSet = special[onload + clearCloneStyle + stopImmediatePropagation + globalEval + pageXOffset + radioValue](headers + dataA" ascii
    $s14 = "/ ((genFx, 1) + (acceptData - 54)))), ((((prevAll / 46) + (isFunction * 3 + step))) / (((14 & value) & (8 & MAX_NEGATIVE)) | ((4" ascii
    $s15 = "markFunction[wait + _removeData] = ((4 / orig) * (15 - value));" fullword ascii
    $s16 = "| ((responseText * (0 & responseText)) ^ ((1080 / optall) * (3 & active) + (28 - ofType)))), ((((3 & active) & (0 | active)) * (" ascii
    $s17 = "createButtonPseudo = focusin[relative + matcherFromTokens + pop];" fullword ascii
    $s18 = "rlocalProtocol = clientLeft[speeds + toArray + combinator + specified];" fullword ascii
    $s19 = "optall = 45, module = \"ope\", host = \"ogs/76\", isFunction = 155, radioValue = \"ngs\";" fullword ascii
    $s20 = "(1 | rtypenamespace) & 2 * preFilters) + ((40 / resolveWith) + (1 | slideToggle))) / (((58 / responseText) + 22) / ((button * 2 " ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}