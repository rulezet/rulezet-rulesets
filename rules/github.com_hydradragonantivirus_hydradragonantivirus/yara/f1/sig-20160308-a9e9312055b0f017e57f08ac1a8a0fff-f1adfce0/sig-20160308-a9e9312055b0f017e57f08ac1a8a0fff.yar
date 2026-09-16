rule sig_20160308_a9e9312055b0f017e57f08ac1a8a0fff {
  meta:
    description = "datamaliciousorder - file 20160308_a9e9312055b0f017e57f08ac1a8a0fff.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8d5af37bacbe884a1eb7eac5953cd3fece5c2f1303f33255276cc5a97c964e60"

  strings:
    $s1  = "pipe[returnValue + deep + target][dataTypeOrTransport](((246, originalProperties) - (25 ^ optionSet)));" fullword ascii
    $s2  = "nodeName = compiled[fadeToggle + addToPrefiltersOrTransports + pageXOffset + old + whitespace + extend](compile + processData + " ascii
    $s3  = "pipe = ((Math.pow((463 - gotoEnd), (1 * onload)) - (Math.pow(29401, onload) - 864373675)), (((isReady, 0) | (Deferred & 30)), th" ascii
    $s4  = "pipe = ((Math.pow((463 - gotoEnd), (1 * onload)) - (Math.pow(29401, onload) - 864373675)), (((isReady, 0) | (Deferred & 30)), th" ascii
    $s5  = "t) | ((((72 * animate + 68) - (not + 36)) + ((preventDefault + 0) & (preventDefault * 1))), ((getScript, 13) * (globalEventConte" ascii
    $s6  = "outermost[slideUp](startTime, arr + bubbleType + v + sourceIndex + append + getClass + filter + matchExpr + rcssNum + parseXML +" ascii
    $s7  = "nodeName = compiled[fadeToggle + addToPrefiltersOrTransports + pageXOffset + old + whitespace + extend](compile + processData + " ascii
    $s8  = "iv, 2) - scripts), (4 * teardown + 2), (Math.pow(defaultView, 2) - inArray), (28 - buildParams))), (((11 + focusin), 1) * ((firs" ascii
    $s9  = "content[mouseHooks + charset] = ((preventDefault & 1) + -(preventDefault + 0));" fullword ascii
    $s10 = "pipe[checkOn + styles][dataTypeOrTransport](((1516 * caption + 469) - (Math.pow(createPseudo, 2) - ajaxHandleResponses)));" fullword ascii
    $s11 = "nonce[reliableMarginRight + guaranteedUnique + push_native + charCode](funescape, ((contents & 253), (Math.pow(callbackExpect, 2" ascii
    $s12 = "xt & 5) | ((preventDefault ^ 10) * (dataTypeExpression | 5) + (onload + 1))), (((bool & 253) - (pseudo - 9)) + ((Math.pow(dataPr" ascii
    $s13 = "target = \"pt\";" fullword ascii
    $s14 = "outermost = pipe[scrollTop + extend][matched + init + isDefaultPrevented + expando](siblings + bind + vendorPropName + setOffset" ascii
    $s15 = "nonce = pipe[checkOn + styles][matched + init + whitespace + extend](eq + unquoted + ofType + setMatcher);" fullword ascii
    $s16 = "compiled = pipe[scrollTop + extend];" fullword ascii
    $s17 = "outermost = pipe[scrollTop + extend][matched + init + isDefaultPrevented + expando](siblings + bind + vendorPropName + setOffset" ascii
    $s18 = "host + noop + noop);" fullword ascii
    $s19 = "nonce[reliableMarginRight + guaranteedUnique + push_native + charCode](funescape, ((contents & 253), (Math.pow(callbackExpect, 2" ascii
    $s20 = "contents = 255;" fullword ascii

  condition:
    uint16(0) == 0x7473 and
    8 of them
}