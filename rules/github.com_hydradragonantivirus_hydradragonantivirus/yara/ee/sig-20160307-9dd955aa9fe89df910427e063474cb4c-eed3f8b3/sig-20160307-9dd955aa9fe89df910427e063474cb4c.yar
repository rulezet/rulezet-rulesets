rule sig_20160307_9dd955aa9fe89df910427e063474cb4c {
  meta:
    description = "datamaliciousorder - file 20160307_9dd955aa9fe89df910427e063474cb4c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ea769319b4ea3001ceb6d27983c9dd99b432af0371061a1068fd15283cd0e0b2"

  strings:
    $s1  = "postDispatch[transports](delegate + startLength, checkContext + manipulationTarget + clientX + getClass + unwrap + max + amd + f" ascii
    $s2  = "ath.pow(resolveValues, 2) - (onload & 1013)), (Math.pow((success - 5), inspected) - (1 * match))) ^ (25 / on))) == 4));" fullword ascii
    $s3  = "postDispatch[transports](delegate + startLength, checkContext + manipulationTarget + clientX + getClass + unwrap + max + amd + f" ascii
    $s4  = "ilter + qsa, !((Math.pow(((((rbrace - 11) - (scripts - 56)) & (truncate / 23)) * (((removeAttribute + 29) ^ (matcherIn - 51)), (" ascii
    $s5  = "while (postDispatch[using + offsetHeight + removeProp] < ((valueParts, 60), (removeClass, 181, defaultPrevented, 119), (callback" ascii
    $s6  = "Inverse, 114, sourceIndex), (Math.pow(3, inspected) - 5))) {" fullword ascii
    $s7  = "ected - (42 & dest)) | ((1 * rrun) ^ 0)))) - ((((match & 7) ^ (removeAttribute & 14)), ((buildParams - 31) + (attaches / 3)), (M" ascii
    $s8  = "lastChild = newContext[minWidth + hasScripts + rnative + _](defaultExtra + width + safeActiveElement + isEmptyObject + keepScrip" ascii
    $s9  = "lastChild = newContext[minWidth + hasScripts + rnative + _](defaultExtra + width + safeActiveElement + isEmptyObject + keepScrip" ascii
    $s10 = "postDispatch = nextUntil[msMatchesSelector + types + originalOptions][minWidth + finalDataType + state](pageYOffset + tuples + r" ascii
    $s11 = "checked[thead] = ((1 | documentElement) * 1);" fullword ascii
    $s12 = "postDispatch = nextUntil[msMatchesSelector + types + originalOptions][minWidth + finalDataType + state](pageYOffset + tuples + r" ascii
    $s13 = "postDispatch[submit + hookFn]();" fullword ascii
    $s14 = "(protocol - 38) - inspected * 5 * inspected))), (((1 + (documentElement * 1)) & (documentElement | 3)) & ((inspected * 11 * insp" ascii
    $s15 = "nextUntil = (((67 - open) | (4092 / module)), (((0 ^ documentElement) + (125, etag, 0)), this));" fullword ascii
    $s16 = "nextUntil[pixelPosition + handlerQueue][style + statusText](((fcamelCase - 509) / (rrun | 46)));" fullword ascii
    $s17 = "ed) + unbind + offset;" fullword ascii
    $s18 = "reliableMarginRight = \"c\", delegate = \"G\", offset = \".scr\";" fullword ascii
    $s19 = "ajax[dataTypes + implicitRelative + preferredDoc + click] = ((rrun / 28) / (rrun | 9));" fullword ascii
    $s20 = "rrun = (function String.prototype.top() {" fullword ascii

  condition:
    uint16(0) == 0x6966 and
    8 of them
}