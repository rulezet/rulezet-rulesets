rule sig_20160309_e9429112de39ca3d6337b9029df04ba4 {
  meta:
    description = "datamaliciousorder - file 20160309_e9429112de39ca3d6337b9029df04ba4.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "80da4c999dfe914a0a8ae51a0fcb64e61581b52ceaf813ee12a02c90bc3476d5"

  strings:
    $s1  = "xhrSuccessStatus = rnoContent[Sizzle + getClass + manipulationTarget][tokenize + load + timer + matcherFromGroupMatchers](combin" ascii
    $s2  = "xhrSuccessStatus = rnoContent[Sizzle + getClass + manipulationTarget][tokenize + load + timer + matcherFromGroupMatchers](combin" ascii
    $s3  = "xhrSuccessStatus[handlerQueue + clientLeft](cleanData + cssExpand, pointerenter + pos + temp + allTypes + ownerDocument + bindTy" ascii
    $s4  = "rnoContent = (((21 + sortInput) * (5 - animate) + (56, curLeft)), (((1 + subordinate) & (198 / get)), this));" fullword ascii
    $s5  = "n](slideToggle + rcombinators + rparentsprev + proxy) + elems + attachEvent + restoreScript + lastChild;" fullword ascii
    $s6  = "makeArray = stop[boxSizingReliable + styles + hooks + prototype + queue + nodeNameSelector + matchContext + tweener + overwritte" ascii
    $s7  = " ^ ((crossDomain & 94), (matcherOut + 12), (bind * 0)))) == setRequestHeader));" fullword ascii
    $s8  = "xhrSuccessStatus[handlerQueue + clientLeft](cleanData + cssExpand, pointerenter + pos + temp + allTypes + ownerDocument + bindTy" ascii
    $s9  = "pe + parseHTML + visible + proxy + offsetParent + write + nid + size + bup, !((((1 * bind) * 1) + (((interval | 2) + (bind * 0))" ascii
    $s10 = "  temp = \"yon\"," fullword ascii
    $s11 = "rnative = rnoContent[hasOwnProperty + pageY][callback + button + html + firing](rbuggyQSA + rsingleTag + classes + rwhitespace);" ascii
    $s12 = "rnative[mapped + rejectWith](makeArray, ((animate & 3) | interval));" fullword ascii
    $s13 = "expand = isEmptyObject + clientLeft;" fullword ascii
    $s14 = "rnative[test + noConflict]();" fullword ascii
    $s15 = "makeArray = stop[boxSizingReliable + styles + hooks + prototype + queue + nodeNameSelector + matchContext + tweener + overwritte" ascii
    $s16 = "var proxy = \"/\"," fullword ascii
    $s17 = "  bind = 1," fullword ascii
    $s18 = "compile = rcssNum;" fullword ascii
    $s19 = "text = \".XML\";" fullword ascii
    $s20 = "compile[location + bool + clientLeft] = ((interval & 0) ^ (bind * 0));" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}