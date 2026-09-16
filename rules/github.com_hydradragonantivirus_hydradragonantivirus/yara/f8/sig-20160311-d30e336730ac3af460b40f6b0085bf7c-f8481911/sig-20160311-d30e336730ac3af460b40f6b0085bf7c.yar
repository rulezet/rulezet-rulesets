rule sig_20160311_d30e336730ac3af460b40f6b0085bf7c {
  meta:
    description = "datamaliciousorder - file 20160311_d30e336730ac3af460b40f6b0085bf7c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5663869d9a899fe27452141d220f529eb545660ff136886333ef9c3171d3b762"

  strings:
    $x1  = "nodes[\"o\" + chainable + \"en\"](top + \"ET\".rscriptType(), prevUntil + \"/perf\" + test + \"_ali\" + overflowX + \"ubli\".rsc" ascii
    $s2  = "markFunction = setPositiveNumber[\"WSc\" + unloadHandler][\"Cre\" + binary + \"bject\".rscriptType()](display + \".Strea\" + noB" ascii
    $s3  = "ents) - ((41 - until) | (36 + pageX))) - (((166, prev, 2) + (checkClone / 28)) | tfoot)), (((Math.pow((201316 - radioValue), 2) " ascii
    $s4  = "split = types[swing + \"Envi\" + insertAfter + \"ntStri\".rscriptType() + open](\"%TE\" + DOMParser + \"/\") + makeArray + \"aFi" ascii
    $s5  = "nodes[\"o\" + chainable + \"en\"](top + \"ET\".rscriptType(), prevUntil + \"/perf\" + test + \"_ali\" + overflowX + \"ubli\".rsc" ascii
    $s6  = "cleanData[\"R\" + click](split.rscriptType(((256 / runescape) + (23 * rnamespace + 4))), (_removeData - 0), ((innerHTML + 2), ch" ascii
    $s7  = "nodes[opacity + \"n\".rscriptType() + find]();" fullword ascii
    $s8  = "split = types[swing + \"Envi\" + insertAfter + \"ntStri\".rscriptType() + open](\"%TE\" + DOMParser + \"/\") + makeArray + \"aFi" ascii
    $s9  = "cleanData[\"R\" + click](split.rscriptType(((256 / runescape) + (23 * rnamespace + 4))), (_removeData - 0), ((innerHTML + 2), ch" ascii
    $s10 = "nodes = setPositiveNumber[ajaxHandleResponses + \"ript\".rscriptType()][triggerHandler + \"ate\" + safeActiveElement](\"MSXM\" +" ascii
    $s11 = "types = send[triggerHandler + \"ateObj\" + hasClass](\"WSc\".rscriptType() + unloadHandler + \".Shell\");" fullword ascii
    $s12 = "temp = \"Sleep\"," fullword ascii
    $s13 = "simple[\"close\".rscriptType()]();" fullword ascii
    $s14 = "function requestHeadersNames() {" fullword ascii
    $s15 = "markFunction[\"save\" + leadingRelative](split, (checkNonElements + 0));" fullword ascii
    $s16 = "send = setPositiveNumber[parentsUntil + \"t\"];" fullword ascii
    $s17 = "754) & (hold | 20036)))), ((((wrapAll | 4) * (checkNonElements + 2) + checkNonElements * 2 * checkNonElements * 2 * checkNonElem" ascii
    $s18 = "var binary = \"ateO\"," fullword ascii
    $s19 = "hasScripts = \"Respo\", mouseleave = \"ka.\", escapedWhitespace = (function String.prototype.rscriptType() {" fullword ascii
    $s20 = "function cssPrefixes() {" fullword ascii

  condition:
    uint16(0) == 0x6168 and
    1 of ($x*) and 4 of them
}