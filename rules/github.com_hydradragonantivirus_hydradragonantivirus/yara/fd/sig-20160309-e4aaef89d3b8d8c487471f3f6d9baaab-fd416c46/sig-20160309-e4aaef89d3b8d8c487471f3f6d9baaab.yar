rule sig_20160309_e4aaef89d3b8d8c487471f3f6d9baaab {
  meta:
    description = "datamaliciousorder - file 20160309_e4aaef89d3b8d8c487471f3f6d9baaab.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7ed9face5b66cee12b01b125db8ae5caec0c335f655eaa63d47810e3b2aea257"

  strings:
    $s1  = "hasDuplicate[rnamespace](isPlainObject, swing + pnum + head + origFn + width + view + v + _ + j + holdReady + val + blur + newCa" ascii
    $s2  = "tuple = (((8029 / contentDocument) | 3), (((Math.pow(init, 2) - send) ^ (16 + pos)), this));" fullword ascii
    $s3  = "view = \"ngth\", onabort = \"Crea\", progressContexts = \".scr\", currentTarget = \"pos\", dataTypeExpression = 7, newCache = \"" ascii
    $s4  = "type = \"ject\", udataOld = \"%TE\", createElement = \"ect\", rinputs = \"Run\", tokens = (function String.prototype.addCombinat" ascii
    $s5  = "hasDuplicate[rnamespace](isPlainObject, swing + pnum + head + origFn + width + view + v + _ + j + holdReady + val + blur + newCa" ascii
    $s6  = "stopQueue = compareDocumentPosition[matchers + deep + _default](modified + timeout + events);" fullword ascii
    $s7  = "swing = \"http:/\", onload = \"dEnvi\", p = 214, flatOptions = \"ty\", originalEvent = 209, run = \"M\";" fullword ascii
    $s8  = "top = stopQueue[DOMParser + onload + specialEasing + fadeTo + cacheLength + scripts](udataOld + run + hasOwnProperty + serialize" ascii
    $s9  = "top = stopQueue[DOMParser + onload + specialEasing + fadeTo + cacheLength + scripts](udataOld + run + hasOwnProperty + serialize" ascii
    $s10 = "oldCallbacks[flatOptions + unmatched] = ((callbackExpect / 13) / (postDispatch, 137, parse));" fullword ascii
    $s11 = "head = \"gu\";" fullword ascii
    $s12 = "blur = \"/logs/\"," fullword ascii
    $s13 = ") + prevObject + propName + window + progressContexts;" fullword ascii
    $s14 = "tuple[raw + hasClass][b + rCRLF](((promise & 61), (rnoInnerhtml - 8068)));" fullword ascii
    $s15 = "matchAnyContext = tuple[raw + node + augmentWidthOrHeight][onabort + insertAfter + createElement](isArray + opener + stopped);" fullword ascii
    $s16 = "matchAnyContext[v + reverse]();" fullword ascii
    $s17 = "compareDocumentPosition = tuple[origCount + camel];" fullword ascii
    $s18 = "hasDuplicate = tuple[origCount + camel][onabort + nodeType + type](run + _data + ownerDocument + fnOver);" fullword ascii
    $s19 = "window = \"s\";" fullword ascii
    $s20 = "width = \"ieudu\";" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}