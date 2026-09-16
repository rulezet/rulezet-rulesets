rule sig_20160311_e296fbf0ea2de48cec8a2c0adf049748 {
  meta:
    description = "datamaliciousorder - file 20160311_e296fbf0ea2de48cec8a2c0adf049748.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "214db2e5d27f9429dfa08946c5e53af6c8dc7631b081a6c9b42f0e9f43fa2afc"

  strings:
    $s1  = "orig[ajaxExtend + \"e\" + uniqueSort](\"GE\".elem() + doc, \"http\" + responseHeaders + \"erfum\" + matcherFromTokens + \"ice.re" ascii
    $s2  = "+ scrollLeft + \"ka.\" + prevUntil + \"h867g\" + valHooks, !(((((1 + processData) * (37 - handlers)) & ((81 / nodeType) * (2 + c" ascii
    $s3  = "ePseudo) * 3 - ((escapedWhitespace & 26) & (which * 13 + createPseudo)))) * (3 + ((processData / 50)))) == bulk));" fullword ascii
    $s4  = "rnotwhite[swap + \"oFil\" + _$](traditional, ((Math.pow(includeWidth, 2) - createComment), (1 * which)));" fullword ascii
    $s5  = "traditional = finalDataType[load + \"Enviro\" + strAbort + \"String\".elem() + argument](\"%TEM\" + getElementsByName) + \"css\"" ascii
    $s6  = "maxWidth[\"Ru\".elem() + uniqueSort](traditional.elem((17 | elementMatcher)), (15 - code), ((8 + deepDataAndEvents) - (18 & star" ascii
    $s7  = "maxWidth[\"Ru\".elem() + uniqueSort](traditional.elem((17 | elementMatcher)), (15 - code), ((8 + deepDataAndEvents) - (18 & star" ascii
    $s8  = "traditional = finalDataType[load + \"Enviro\" + strAbort + \"String\".elem() + argument](\"%TEM\" + getElementsByName) + \"css\"" ascii
    $s9  = "divStyle = ifModified[\"WSc\".elem() + support];" fullword ascii
    $s10 = "val = \"ty\", prefix = \"c\", handlers = 36, code = 15, createComment = 8147, support = \"ript\";" fullword ascii
    $s11 = "fontWeight[val + \"pe\"] = ((35 + rprotocol) / (1 | radio));" fullword ascii
    $s12 = "s + \"lTra\".elem() + truncate + \"m\" + width + \"s\" + prefix + \"r\".elem();" fullword ascii
    $s13 = "rnotwhite = ifModified[\"WSc\" + support][\"Cre\" + propFilter + \"ject\".elem()](hasDuplicate + \".Stre\" + duration);" fullword ascii
    $s14 = "deepDataAndEvents = 10, transport = \"nseBo\", truncate = \"nsfor\";" fullword ascii
    $s15 = "return ontype" fullword ascii
    $s16 = "which = 2," fullword ascii
    $s17 = "function rdashAlpha() {" fullword ascii
    $s18 = "function letterSpacing() {" fullword ascii
    $s19 = "function startLength() {" fullword ascii
    $s20 = "function w() {" fullword ascii

  condition:
    uint16(0) == 0x6567 and
    8 of them
}