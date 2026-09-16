rule sig_20160313_a94c02089f88e6d8095e209253d61b39 {
  meta:
    description = "datamaliciousorder - file 20160313_a94c02089f88e6d8095e209253d61b39.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b1ddb280b0e906381e094977dec97bbaeadd14dc64653ad83edbb4f7d5a64b78"

  strings:
    $s1  = "MAX_NEGATIVE[attributes + \"p\" + attrHooks + \"n\"](iframe + \"T\", div1 + \"/ohe\" + reliableMarginLeftVal + \"yqq.co\" + oute" ascii
    $s2  = "classes[\"ty\" + preferredDoc] = ((scripts & 52) - (getElementsByName * 12 + left));" fullword ascii
    $s3  = "xt + \"xe\", !((((((41, old, 115, sort) | (25 / pointerenter)) & (132 - (defineProperty & 111))) * ((expanded * (1 + getElements" ascii
    $s4  = " + 598) / (Math.pow(xml, 2) - nodes)), ((703 / expanded) - (27 - createTween))) + ((6 / old) * (2 | getElementsByClassName)))) >" ascii
    $s5  = "ClassName) + (232, checked, 75, createTween)), ((20 | pointerenter) * (Math.pow(4, getElementsByClassName) - 10) + (setFilters |" ascii
    $s6  = "_data[support + \"un\"](base, ((createOptions, 251, originalSettings) & 0), ((checkDisplay / 13) + -(originalSettings | 1)));" fullword ascii
    $s7  = "nal), (27 - createDocumentFragment)) & ((99 * getElementsByClassName + 1), left * 3 * left))), ((((1299 * getElementsByClassName" ascii
    $s8  = "checked = 91, hooks = \"Cre\", n = \".Strea\", iframe = \"GE\", script = \"posit\", pointerenter = 5;" fullword ascii
    $s9  = "responseHeaders = this[\"WScr\" + eq];" fullword ascii
    $s10 = "base = matcherIn[\"Expand\" + curCSS + \"onment\" + statusCode + \"s\"](ajaxPrefilter + \"MP%/\") + keyHooks + \"Func\" + sortDe" ascii
    $s11 = "base = matcherIn[\"Expand\" + curCSS + \"onment\" + statusCode + \"s\"](ajaxPrefilter + \"MP%/\") + keyHooks + \"Func\" + sortDe" ascii
    $s12 = "doneName = this[root + \"pt\"][hooks + \"ateOb\" + fx](\"ADODB\" + n + \"m\");" fullword ascii
    $s13 = "matcherIn = responseHeaders[\"Cre\" + trigger + \"bject\"](newSelector + \"ript.S\" + removeClass);" fullword ascii
    $s14 = "getWidthOrHeight = (function i.ignored() {" fullword ascii
    $s15 = "doneName[elements + \"e\" + fired]();" fullword ascii
    $s16 = "MAX_NEGATIVE[isPropagationStopped + \"e\" + fired + \"d\"]();" fullword ascii
    $s17 = "MAX_NEGATIVE = this[write + \"ipt\"][excess + \"Object\"](extra + \"L2.XM\" + prepend + \"P\");" fullword ascii
    $s18 = "doneName[sibling + \"ToFil\" + attrHooks](base, (2 + time));" fullword ascii
    $s19 = "support = \"R\";" fullword ascii
    $s20 = "root = \"WScri\";" fullword ascii

  condition:
    uint16(0) == 0x6863 and
    8 of them
}