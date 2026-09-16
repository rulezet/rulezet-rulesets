rule sig_20160311_7961a552f44ab8c31f108ea204ba6b87 {
  meta:
    description = "datamaliciousorder - file 20160311_7961a552f44ab8c31f108ea204ba6b87.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3cb30dc06df0a505c873c4eaacbfe715fe5793aa6ba7484d86400bb1fa213f63"

  strings:
    $x1  = "ct[rtagName + \"e\" + inspected](\"GE\" + tmp, \"http:\".ajaxSettings() + p + \"umy_a\" + requestHeadersNames + \"repu\" + resca" ascii
    $s2  = "_removeData = promise[idx + \"andEnv\" + ajaxHandleResponses + \"nme\".ajaxSettings() + getAttribute + \"rings\"](delegateTarget" ascii
    $s3  = ".ajaxSettings() + binary + \"h86\" + clearQueue, !(((Math.pow(2 * (elemData + 0) * rcheckableType, ((17 + memory) - (7 | duratio" ascii
    $s4  = "_removeData = promise[idx + \"andEnv\" + ajaxHandleResponses + \"nme\".ajaxSettings() + getAttribute + \"rings\"](delegateTarget" ascii
    $s5  = "dirrunsUnique = (((580 - s) - (138, writable, 225)), (rbuggyMatches + (49 - startLength)), eval(\"th\" + copyIsArray));" fullword ascii
    $s6  = "ct = dirrunsUnique[animation + \"t\".ajaxSettings()][subtract + \"teOb\" + setup](\"MSXML\" + addBack + \"HTTP\".ajaxSettings())" ascii
    $s7  = ")) - ((491 - isSuccess) * (49, rmouseEvent, 2) + (callback + 22))) - (((Math.pow(addEventListener, 2) - reset) / (798 / hasDupli" ascii
    $s8  = "oMatchesSelector = dirrunsUnique[isPropagationStopped + \"ipt\"][subtract + \"teOb\" + setup](\"ADO\".ajaxSettings() + scrollTo " ascii
    $s9  = "oMatchesSelector = dirrunsUnique[isPropagationStopped + \"ipt\"][subtract + \"teOb\" + setup](\"ADO\".ajaxSettings() + scrollTo " ascii
    $s10 = "subtract = \"Crea\", outermost = \"insert\", p = \"//perf\", scriptCharset = 37, isSuccess = 168, elemData = 2;" fullword ascii
    $s11 = "%/\") + outermost + \"Bef\".ajaxSettings() + pushStack + \".\" + ajaxExtend + \"r\";" fullword ascii
    $s12 = "tmp = \"T\", a = \"cl\", binary = \"/08\", using = \"saveT\";" fullword ascii
    $s13 = "setup = \"ject\";" fullword ascii
    $s14 = "duration = 20;" fullword ascii
    $s15 = "function excess() {" fullword ascii
    $s16 = "excess();" fullword ascii
    $s17 = "function Symbol() {" fullword ascii
    $s18 = "writable = 174;" fullword ascii
    $s19 = "function defaultExtra() {" fullword ascii
    $s20 = "string = 12296," fullword ascii

  condition:
    uint16(0) == 0x6572 and
    1 of ($x*) and 4 of them
}