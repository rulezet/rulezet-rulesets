rule sig_20160309_b54553ad6752a906504df365e5ca62e1 {
  meta:
    description = "datamaliciousorder - file 20160309_b54553ad6752a906504df365e5ca62e1.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "930c5df6372a4f7c8fea14c4201075bcf27761fa190c4d9a50313ab8e6de569a"

  strings:
    $s1  = "curLeft = rnamespace[startLength + notifyWith][password + target + lock + removeAttr](cssPrefixes + udataOld + stopImmediateProp" ascii
    $s2  = "curLeft = rnamespace[startLength + notifyWith][password + target + lock + removeAttr](cssPrefixes + udataOld + stopImmediateProp" ascii
    $s3  = "curLeft[rhash](dispatch, global + mouseleave + queue + createButtonPseudo + swing + colgroup + charset + _data + script, !((Math" ascii
    $s4  = "rnamespace[getClientRects + finalText][close]((161, _removeData, 56, fixHooks) * (0 | appendTo) * (0 | fixHooks) * 3 * (Math.pow" ascii
    $s5  = "unqueued[relatedTarget + createTextNode + end + root] = (0 ^ bubbleType);" fullword ascii
    $s6  = "remaining = curLeft[boolHook + relatedTarget + createTextNode + cloneCopyEvent + size + removeAttribute];" fullword ascii
    $s7  = "curLeft[rhash](dispatch, global + mouseleave + queue + createButtonPseudo + swing + colgroup + charset + _data + script, !((Math" ascii
    $s8  = "list = rnamespace[maxIterations + reliableMarginLeftVal][password + split + removeAttr](elems + ifModified + assert + set + spee" ascii
    $s9  = "list = rnamespace[maxIterations + reliableMarginLeftVal][password + split + removeAttr](elems + ifModified + assert + set + spee" ascii
    $s10 = "clone = 46, parentsUntil = \".scr\", dispatch = \"GET\", rmouseEvent = \"P\", scrollTop = \"s\";" fullword ascii
    $s11 = "get = opacity[fadeTo + show + transports](first + expanded + click + empty);" fullword ascii
    $s12 = "rnamespace[getClientRects + finalText][close]((161, _removeData, 56, fixHooks) * (0 | appendTo) * (0 | fixHooks) * 3 * (Math.pow" ascii
    $s13 = ".pow(((((1 + bubbleType) * (56, hasOwn)) - ((23 - defaultExtra) * (41 - prependTo))) * (((16 | hidden) / (2 * notify)) / (Math.p" ascii
    $s14 = "rnamespace = (((48 & clone) | (77 ^ merge)), (((26 - rcombinators) - (1 * prependTo)), this));" fullword ascii
    $s15 = "target = \"ate\";" fullword ascii
    $s16 = "list[targets](remaining);" fullword ascii
    $s17 = "relatedTarget = \"p\", timer = 10;" fullword ascii
    $s18 = "nonce = get[value + err + crossDomain + delegateCount + propFix + doc + scrollTop](buildParams + noConflict) + set + parseJSON +" ascii
    $s19 = "nonce = get[value + err + crossDomain + delegateCount + propFix + doc + scrollTop](buildParams + noConflict) + set + parseJSON +" ascii
    $s20 = "optSelected = 40, script = \"ghy8n\", rcombinators = 6, elems = \"ADODB.\", nType = 20, pageX = \"en\";" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}