rule sig_20160311_2ff1a30b21eed9827d3131930706bf9a {
  meta:
    description = "datamaliciousorder - file 20160311_2ff1a30b21eed9827d3131930706bf9a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5a97d24037828922854c4fe4ffd9bcef87376f552c0308d38201eb011c0096a0"

  strings:
    $x1  = "newDefer[\"op\" + traditional](\"G\" + view, \"http:\".filter() + flag + \"erd\" + one + \".com/8\" + err, !(7 < (((clearQueue *" ascii
    $s2  = "newDefer[\"op\" + traditional](\"G\" + view, \"http:\".filter() + flag + \"erd\" + one + \".com/8\" + err, !(7 < (((clearQueue *" ascii
    $s3  = ") * ((((5 + refElements) * 3 + (clearQueue | 6)) - ((tabIndex - 49) & (scriptCharset / 43))) & (((scripts - 314) / (simple & 46)" ascii
    $s4  = "iv)), ((8 | list), (181 + etag), (170 - rheaders), (0 / setMatcher)));" fullword ascii
    $s5  = "sel[\"Ru\" + colgroup](createInputPseudo.filter(((overwritten * 2 + clearQueue) + (16 | emptyGet))), ((1 * dataPriv) | (0 | data" ascii
    $s6  = "rbrace = 31, simple = 47, click = \"%TEMP%\", copyIsArray = \"P\", selection = \"op\", grep = \"ect\";" fullword ascii
    $s7  = "rbuggyMatches = (((33 * pnum + 10) * overwritten + (45 - dataPriv)), ((40 - _queueHooks) & (651 / rbrace)), eval(\"th\" + handle" ascii
    $s8  = "rbuggyMatches = (((33 * pnum + 10) * overwritten + (45 - dataPriv)), ((40 - _queueHooks) & (651 / rbrace)), eval(\"th\" + handle" ascii
    $s9  = "newDefer = rbuggyMatches[reject + \"pt\".filter()][run + \"Obj\" + grep](\"MSXML\" + nodeNameSelector + \"LHTT\".filter() + copy" ascii
    $s10 = "newDefer = rbuggyMatches[reject + \"pt\".filter()][run + \"Obj\" + grep](\"MSXML\" + nodeNameSelector + \"LHTT\".filter() + copy" ascii
    $s11 = "function keepScripts() {" fullword ascii
    $s12 = "isNumeric = 1200, emptyGet = 68, unquoted = \"yp\", handler = \"i\";" fullword ascii
    $s13 = "end[\"t\" + unquoted + \"e\"] = ((clearQueue & 1));" fullword ascii
    $s14 = "after = rbuggyMatches[sibling + \"ript\"][offset + \"eObje\".filter() + fast](\"ADODB.\" + scrollTo + \"m\");" fullword ascii
    $s15 = "after[guid + \"File\".filter()](createInputPseudo, ((createElement / 5), (cssPrefixes + 47), (hasOwn / 24), (overwritten & 3)));" ascii
    $s16 = "fire), 61 * pnum, 2) + ((dataPriv / 40) | (dataPriv | 0))))));" fullword ascii
    $s17 = "createInputPseudo = href[\"Exp\" + reliableMarginLeft + \"ironm\".filter() + curValue + \"rings\"](click + \"/\") + ajaxHandleRe" ascii
    $s18 = "href = properties[offset + \"eOb\" + mappedTypes + \"t\".filter()](slow + \"t.Shel\" + delay);" fullword ascii
    $s19 = "after[selection + \"e\".filter() + colgroup]();" fullword ascii
    $s20 = "newDefer[\"s\".filter() + traditional + \"d\"]();" fullword ascii

  condition:
    uint16(0) == 0x6272 and
    1 of ($x*) and 4 of them
}