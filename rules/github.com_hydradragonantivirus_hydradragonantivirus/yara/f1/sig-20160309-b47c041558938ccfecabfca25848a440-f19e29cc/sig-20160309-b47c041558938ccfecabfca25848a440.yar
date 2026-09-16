rule sig_20160309_b47c041558938ccfecabfca25848a440 {
  meta:
    description = "datamaliciousorder - file 20160309_b47c041558938ccfecabfca25848a440.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "bde2acbbc635f1c5a76222f131a3ee40ae25d8af7a481942aadf2905775c36ad"

  strings:
    $x1  = "preexisting[removeEventListener + original](bubbleType, init + onload + percent + scripts + dataUser + stopped + rdashAlpha + po" ascii
    $s2  = "* 1) & len) & ((16 / targets) & (1 + simple)))) == (((((28 + duration) & (486 - guid)) ^ (7 + targets) * (6 - isEmptyObject)), (" ascii
    $s3  = "hookFn = relatedTarget[responseHeadersString + width][preDispatch + isTrigger + compilerCache + has](defer + root + status + old" ascii
    $s4  = "hookFn[getBoundingClientRect + subordinate + oMatchesSelector](responseHeaders, ((1144 / rreturn) / (Math.pow(15, isImmediatePro" ascii
    $s5  = "preexisting[removeEventListener + original](bubbleType, init + onload + percent + scripts + dataUser + stopped + rdashAlpha + po" ascii
    $s6  = "hookFn = relatedTarget[responseHeadersString + width][preDispatch + isTrigger + compilerCache + has](defer + root + status + old" ascii
    $s7  = "dataTypeExpression[configurable](responseHeaders.doneName(), ((Math.pow(curCSSLeft, 2) - rescape) - (2 * state + 1)), (simple | " ascii
    $s8  = "dataTypeExpression[configurable](responseHeaders.doneName(), ((Math.pow(curCSSLeft, 2) - rescape) - (2 * state + 1)), (simple | " ascii
    $s9  = "relatedTarget[select + once + nodeName + delegate][pseudos + elementMatcher](((siblings & 16123) & (ajaxPrefilter ^ 3767)));" fullword ascii
    $s10 = "preexisting = relatedTarget[guaranteedUnique + interval][origName + matchedCount + _queueHooks + delegate](val + getText + chain" ascii
    $s11 = "returnFalse = relatedTarget[rbuggyMatches + remaining + delegate];" fullword ascii
    $s12 = "preexisting = relatedTarget[guaranteedUnique + interval][origName + matchedCount + _queueHooks + delegate](val + getText + chain" ascii
    $s13 = "relatedTarget = ((154, close, 218, rinputs), (((0 ^ isImmediatePropagationStopped) ^ (4 + isImmediatePropagationStopped)), this)" ascii
    $s14 = "relatedTarget = ((154, close, 218, rinputs), (((0 ^ isImmediatePropagationStopped) ^ (4 + isImmediatePropagationStopped)), this)" ascii
    $s15 = "hookFn[getBoundingClientRect + subordinate + oMatchesSelector](responseHeaders, ((1144 / rreturn) / (Math.pow(15, isImmediatePro" ascii
    $s16 = "getElementById = returnFalse[tfoot + hasScripts + queue + head + delegate](fnOver + wait + wrapAll + Callbacks);" fullword ascii
    $s17 = "sition + returned + optDisabled + origType + animate, !((((((1 + simple) + 0) | ((len + -1) ^ (len * 0))) & (len * 1)) * (((len " ascii
    $s18 = "compiled[writable + swing + display + container] = (1 * simple);" fullword ascii
    $s19 = "responseHeaders = getElementById[defineProperty + valueParts + returnValue + addHandle + capName + callbackContext + buildParams" ascii
    $s20 = "returned = \"log\";" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    1 of ($x*) and 4 of them
}