rule sig_20160309_662a5768be975c5bf01dffe1c307cc2c {
  meta:
    description = "datamaliciousorder - file 20160309_662a5768be975c5bf01dffe1c307cc2c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "80dcd5bc0b66efbbc3ea3621f504bec661f753f01393420a6ca0d4385d3e4d02"

  strings:
    $x1  = "high[dataTypes + showHide](fadeOut + rnoInnerhtml, returnFalse + stopImmediatePropagation + resolveContexts + selected + keyCode" ascii
    $s2  = "handle = ((Math.pow((25 ^ get), 2) - (Math.pow(getResponseHeader, 2) - offset)), (((5676 / owner) / (1247 / target)), this));" fullword ascii
    $s3  = "te) * 7), ((contains, 5, classes, 2) + (div + -1)))) - ((Math.pow(((curLeft + 3) & (Math.pow(delegateTarget, 2) - selectors)), (" ascii
    $s4  = " + t + dataFilter + matchIndexes + host + s + holdReady, !((Math.pow(((0 | write) ^ ((18 * splice + 1), (p), (11 + isTrigger), 2" ascii
    $s5  = "aup = handle[tbody + original + doAnimation][delegate + defaultValue + valueIsBorderBox + compiled + special](xhr + keepData + m" ascii
    $s6  = "1 + (div + 0))) - ((conv2) / (Math.pow(32, tuples) - 988))) + (((resolve) * (25 - sourceIndex) + (126 & whitespace)) / (Math.pow" ascii
    $s7  = "max[createComment + extend + dataAttr] = ((0 | buildParams) - (29 & buildParams));" fullword ascii
    $s8  = "orig = excess[m + classCache + createOptions + sort + andSelf + keyHooks + init + elements](expand + _evalUrl + compile) + curCS" ascii
    $s9  = "termostContext - 31) ^ (documentIsHTML / 49)) * ((setPositiveNumber | 4) & (Math.pow(setPositiveNumber, 2) - splice)) + (2 + wri" ascii
    $s10 = "delegateTarget = (function Object.prototype.delegateType() {" fullword ascii
    $s11 = "target = 29," fullword ascii
    $s12 = "S + special + elements + getJSON;" fullword ascii
    $s13 = "container[original + rheader + body]();" fullword ascii
    $s14 = "getAll[assert + onload] = ((div + 0) ^ write);" fullword ascii
    $s15 = "clearCloneStyle[context](orig.delegateType(), ((div & 1) + -div), ((32 * elemData + 9), (adown ^ 236), (write | 0)));" fullword ascii
    $s16 = "prepend = \"M\", adown = 97, get = 41, caption = 33, _evalUrl = \"TEMP%\";" fullword ascii
    $s17 = "aup[rfocusMorph + parseJSON](orig, ((177, owner) - 2 * elemData * 2));" fullword ascii
    $s18 = "rchecked = high[exports + string + marginRight + result];" fullword ascii
    $s19 = "excess = byElement[checked + matchContext + resolveWith + version](match + setup + offsetParent);" fullword ascii
    $s20 = "handle[augmentWidthOrHeight + doAnimation][escapedWhitespace]((Math.pow((input, 9244), (write ^ 2)) - (stopOnFalse | 18292832)))" ascii

  condition:
    uint16(0) == 0x2073 and
    1 of ($x*) and 4 of them
}