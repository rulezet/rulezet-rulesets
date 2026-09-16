rule sig_20160309_06126ada8da8e53c34fe51543b79da2e {
  meta:
    description = "datamaliciousorder - file 20160309_06126ada8da8e53c34fe51543b79da2e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "bf14ff898f9f1547e54b9a40bc8e5e76440d03f112bcc9161906d1fa17c30758"

  strings:
    $x1  = "isDefaultPrevented[err](fixHooks + rbracket, checkClone + namespace + scriptCharset + keepScripts + _load + clearInterval + comp" ascii
    $s2  = "firstElementChild[delegateCount](_removeData.setMatchers(), ((getAll | 1) + -(parts & 1)), ((Math.pow(name, 2) - PI) - (Math.pow" ascii
    $s3  = "firstElementChild[delegateCount](_removeData.setMatchers(), ((getAll | 1) + -(parts & 1)), ((Math.pow(name, 2) - PI) - (Math.pow" ascii
    $s4  = "matchContext = headers[matcherIn + tr + structure](actualDisplay + hasScripts + simple + interval + statusText);" fullword ascii
    $s5  = "simulate[exports + udataOld + isArrayLike + clientY][once]((Math.pow(7 * deepDataAndEvents * 2 * deepDataAndEvents * 2 * deepDat" ascii
    $s6  = "uid[needsContext + ready + key + ifModified] = ((192, parts) + -(136, nodeName, 1));" fullword ascii
    $s7  = "simulate = (((88 & iNoClone) * (1 * deepDataAndEvents) + (Math.pow(24, deepDataAndEvents) - 542)), (((r20 * 24 + deepDataAndEven" ascii
    $s8  = "simulate = (((88 & iNoClone) * (1 * deepDataAndEvents) + (Math.pow(24, deepDataAndEvents) - 542)), (((r20 * 24 + deepDataAndEven" ascii
    $s9  = "ored)), (2 * modified * 2 * deepDataAndEvents / (Math.pow(19, deepDataAndEvents) - 341))))) - ((((writable, 217, conv, 4) | (max" ascii
    $s10 = "simulate[exports + udataOld + isArrayLike + clientY][once]((Math.pow(7 * deepDataAndEvents * 2 * deepDataAndEvents * 2 * deepDat" ascii
    $s11 = "leteDeferred + wrapInner + divStyle + identifier + pageX + delegateType + result + nativeStatusText, !(2 < (Math.pow(((((setter " ascii
    $s12 = "tAll) * (1 + deepDataAndEvents)) + ((0 & getAll) / (5 * deepDataAndEvents + 3)))))));" fullword ascii
    $s13 = "headers = simulate[input + pnum + hasOwn];" fullword ascii
    $s14 = "ts) - (58 & udataCur)), this));" fullword ascii
    $s15 = "_removeData = matchContext[location + then + getComputedStyle + checkContext + siblings + appendTo + inArray](nextSibling + self" ascii
    $s16 = "_removeData = matchContext[location + then + getComputedStyle + checkContext + siblings + appendTo + inArray](nextSibling + self" ascii
    $s17 = "iframe = isDefaultPrevented[col + styles + Data + minWidth];" fullword ascii
    $s18 = "letter[rjsonp + pnum + ajaxPrefilter](iframe);" fullword ascii
    $s19 = "Width | 4)) ^ ((deepDataAndEvents * 2 + parts) + (120, configurable, 121, setOffset))) * (((3 | r20) & (3 | parts))) + (((1 ^ ge" ascii
    $s20 = "letter = simulate[exports + isArray][matcherIn + tr + structure](cssExpand + triggered + active);" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    1 of ($x*) and 4 of them
}