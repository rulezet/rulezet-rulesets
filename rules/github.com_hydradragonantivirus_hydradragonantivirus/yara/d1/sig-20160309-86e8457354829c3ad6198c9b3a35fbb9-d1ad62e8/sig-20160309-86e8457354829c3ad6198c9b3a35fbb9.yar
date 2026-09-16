rule sig_20160309_86e8457354829c3ad6198c9b3a35fbb9 {
  meta:
    description = "datamaliciousorder - file 20160309_86e8457354829c3ad6198c9b3a35fbb9.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "99c240b953d9296d33b4978d0fc30d3767eac8dcf94b26fc77975e1c7fdd1a97"

  strings:
    $s1  = "href = fail[left + self + display + isPlainObject](beforeSend + relatedTarget + isPlainObject + click + eased);" fullword ascii
    $s2  = ", success)) - ((2350 / matchAnyContext) & (611 / propName))) * ((5 * removeProp * 2 & (removeEventListener & 31)) / (Math.pow((s" ascii
    $s3  = "isBorderBox[ajaxConvert](matchedCount, fns + oldCallbacks + callbackInverse + results + rtagName + optgroup + isArrayLike + insp" ascii
    $s4  = "scale = 3, wrapInner = \"ron\", obj = \"leep\", selected = 62, operator = \"e\", width = \"%TEMP%\";" fullword ascii
    $s5  = "fail = handlerQueue[compareDocumentPosition + rwhitespace + finalValue];" fullword ascii
    $s6  = "handlerQueue = (((227 + checkDisplay) & (11186 / matchAnyContext)), (((40, rnumnonpx, 137, returnFalse) / (20 ^ rheaders)), this" ascii
    $s7  = "removeEventListener = 31, eventDoc = \"c\", dirruns = 962, click = \".She\", childNodes = 853;" fullword ascii
    $s8  = "ofType[result + operator] = (223, (scrollTop, 132, val), (1 + win));" fullword ascii
    $s9  = "handlerQueue = (((227 + checkDisplay) & (11186 / matchAnyContext)), (((40, rnumnonpx, 137, returnFalse) / (20 ^ rheaders)), this" ascii
    $s10 = "implementation[tuple + responseText + operator](guaranteedUnique, ((image * 2) | (removeProp | 0)));" fullword ascii
    $s11 = "curLeft[t](guaranteedUnique.funcName(), (1 * win), (0 / (selected - 45)));" fullword ascii
    $s12 = "marginDiv[prev + rsubmittable + transport] = ((0 & image) & 0);" fullword ascii
    $s13 = "keyCode + deep + rbrace);" fullword ascii
    $s14 = "implementation = handlerQueue[beforeSend + finalValue][left + defer + mozMatchesSelector + eventDoc + isPlainObject](domManip + " ascii
    $s15 = "setter = isBorderBox[index + transport + td + disable];" fullword ascii
    $s16 = "isBorderBox = handlerQueue[linear + getClientRects][pageY + rquery + list](show + anim + speed + cacheLength + related);" fullword ascii
    $s17 = "implementation[err + window](setter);" fullword ascii
    $s18 = "implementation = handlerQueue[beforeSend + finalValue][left + defer + mozMatchesSelector + eventDoc + isPlainObject](domManip + " ascii
    $s19 = "cale + 0), (win ^ 2)) - (noop - 14)))) == createPseudo));" fullword ascii
    $s20 = "implementation[tween + prevUntil]();" fullword ascii

  condition:
    uint16(0) == 0x6572 and
    8 of them
}