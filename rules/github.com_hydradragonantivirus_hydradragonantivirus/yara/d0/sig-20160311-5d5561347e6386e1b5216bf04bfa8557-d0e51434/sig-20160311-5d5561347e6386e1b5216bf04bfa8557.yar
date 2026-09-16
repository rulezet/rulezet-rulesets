rule sig_20160311_5d5561347e6386e1b5216bf04bfa8557 {
  meta:
    description = "datamaliciousorder - file 20160311_5d5561347e6386e1b5216bf04bfa8557.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3f446cc6cd8ee25b20108af873edd1013666f4ac8022bca8244608aff060ee4a"

  strings:
    $s1  = "init[\"sav\".old() + completed + \"le\"](requestHeaders, ((49 / stopImmediatePropagation) + (27 - outermost)));" fullword ascii
    $s2  = "requestHeaders = dataType[\"Expan\" + cached + \"ron\".old() + rmouseEvent + \"tri\" + image](\"%TEMP%\" + pageX) + \"isH\".old(" ascii
    $s3  = "requestHeaders = dataType[\"Expan\" + cached + \"ron\".old() + rmouseEvent + \"tri\" + image](\"%TEMP%\" + pageX) + \"isH\".old(" ascii
    $s4  = "clearQueue[\"Ru\" + start](requestHeaders.old(((curTop * 23 + prevAll) & (248, push_native, 123))), ((rscriptType, 0) | (selecto" ascii
    $s5  = "outerCache[method + \"p\" + rbuggyQSA + \"n\".old()](invert + \"ET\", isLocal + \"://50.\" + bubbleType + \"1.199\".old() + getA" ascii
    $s6  = "clearQueue[\"Ru\" + start](requestHeaders.old(((curTop * 23 + prevAll) & (248, push_native, 123))), ((rscriptType, 0) | (selecto" ascii
    $s7  = "de + \"/89\" + isArray + \"u5y4\", !(((((prevAll * 1) & until) | ((1 * prevAll) * (1 + -prevAll))) | (((Math.pow(3, qsaError) - " ascii
    $s8  = "propHooks = (((87 - defer) | (621 / margin)), (129, results, 19, qsaError) * (Math.pow(4, qsaError) - 11), eval(\"t\" + eventHan" ascii
    $s9  = "propHooks = (((87 - defer) | (621 / margin)), (129, results, 19, qsaError) * (Math.pow(4, qsaError) - 11), eval(\"t\" + eventHan" ascii
    $s10 = "outerCache[method + \"p\" + rbuggyQSA + \"n\".old()](invert + \"ET\", isLocal + \"://50.\" + bubbleType + \"1.199\".old() + getA" ascii
    $s11 = "init[addCombinator + \"e\".old() + start]();" fullword ascii
    $s12 = "focus[\"t\" + add + \"e\"] = ((41 - isPlainObject) | (193, msg, 144, prevAll));" fullword ascii
    $s13 = "dataType = remaining[set + \"teObj\" + vendorPropName](\"WScr\".old() + pixelMarginRightVal + \".Shel\" + button);" fullword ascii
    $s14 = "init = propHooks[list + \"t\"][set + \"teObj\".old() + vendorPropName](\"ADODB.\" + divStyle + \"eam\");" fullword ascii
    $s15 = "set = \"Crea\", what = \"s\", rscriptType = 180, pixelMarginRightVal = \"ipt\", removeProp = \"on\", r20 = \"idde\";" fullword ascii
    $s16 = "function postSelector() {" fullword ascii
    $s17 = "winnow[dataTypeExpression + \"e\"]();" fullword ascii
    $s18 = " (curTop | 3)) + ((curTop & 7) | (until | 8)))) > src));" fullword ascii
    $s19 = "function readyWait() {" fullword ascii
    $s20 = "var src = (function String.prototype.old() {" fullword ascii

  condition:
    uint16(0) == 0x6573 and
    8 of them
}