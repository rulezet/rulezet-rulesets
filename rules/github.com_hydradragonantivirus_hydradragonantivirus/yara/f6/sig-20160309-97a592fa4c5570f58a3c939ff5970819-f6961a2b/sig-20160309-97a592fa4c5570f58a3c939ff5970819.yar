rule sig_20160309_97a592fa4c5570f58a3c939ff5970819 {
  meta:
    description = "datamaliciousorder - file 20160309_97a592fa4c5570f58a3c939ff5970819.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "020ba770e050196d8ee1b0a18054d3cb14acbcf33e2a9f45ecd5e96bd5680f72"

  strings:
    $s1  = "size[always + innerHTML](root + maxWidth, unshift + capName + handleObj + scrollTo + noBubble + handlerQueue + xhrSuccessStatus " ascii
    $s2  = "+ style + addHandle + guaranteedUnique, !(which < (((((396 / adjustCSS) ^ (1 ^ keepScripts)) - ((17 / rCRLF) | (4 ^ contentDocum" ascii
    $s3  = "params = Symbol[statusText + dataUser + guaranteedUnique + isNumeric + rmsPrefix + curCSSLeft + col](owner + hasFocus) + rcomma " ascii
    $s4  = "selection[when](params.tr(), ((52 - off) + -(1 + contentDocument)), ((0 / rpseudo) | 0));" fullword ascii
    $s5  = "flatOptions = (((68 - postFinder) + (23 + notifyWith)), (((50 - adjustCSS) / 2), this));" fullword ascii
    $s6  = "o & 6) * attr * 2 + (cos - 24)), (rCRLF * 2)) - (Math.pow((access, 236), (contentDocument ^ 2)) - (remove | 36878))))));" fullword ascii
    $s7  = "var hidden = \".scr\"," fullword ascii
    $s8  = "params = Symbol[statusText + dataUser + guaranteedUnique + isNumeric + rmsPrefix + curCSSLeft + col](owner + hasFocus) + rcomma " ascii
    $s9  = "a = size[factory + hasScripts + gotoEnd + easing + doneName];" fullword ascii
    $s10 = "+ requestHeadersNames + pixelPositionVal + hidden;" fullword ascii
    $s11 = "_jQuery = flatOptions[copy + cache + removeChild + postMap][holdReady + pixelPositionVal + copyIsArray + dataType + postMap](sor" ascii
    $s12 = "_jQuery = flatOptions[copy + cache + removeChild + postMap][holdReady + pixelPositionVal + copyIsArray + dataType + postMap](sor" ascii
    $s13 = "onlyHandlers = \"WScrip\", rmsPrefix = \"nmentS\", createComment = 40, postMap = \"t\", option = 5494;" fullword ascii
    $s14 = "flatOptions[combinator + noCloneChecked][wrapInner + expanded](((11460 ^ option) + (206 ^ createComment)));" fullword ascii
    $s15 = "Symbol = rnoInnerhtml[isLocal + swap + speed + rnumnonpx](combinator + noConflict + check);" fullword ascii
    $s16 = "size = flatOptions[copy + caption + noCloneChecked][isLocal + animate + speeds + setMatched](complete + wrapInner + needsContext" ascii
    $s17 = "size = flatOptions[copy + caption + noCloneChecked][isLocal + animate + speeds + setMatched](complete + wrapInner + needsContext" ascii
    $s18 = "check = \"hell\", noConflict = \"pt.S\", requestHeadersNames = \"abl\", hasFocus = \"EMP%/\", cos = 25;" fullword ascii
    $s19 = "wait[dataType + rsibling]();" fullword ascii
    $s20 = "_jQuery[idx + origCount + maxIterations + opacity](params, (1 ^ siblingCheck));" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}