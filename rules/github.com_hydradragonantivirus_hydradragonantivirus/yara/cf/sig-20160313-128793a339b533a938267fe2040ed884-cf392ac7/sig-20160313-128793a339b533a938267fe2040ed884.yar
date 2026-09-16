rule sig_20160313_128793a339b533a938267fe2040ed884 {
  meta:
    description = "datamaliciousorder - file 20160313_128793a339b533a938267fe2040ed884.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1b6e2d75c125e0cee4cbf53cd3c6cb8680e9be7478136772daa2f5e90692cc65"

  strings:
    $s1  = "matcherIn[\"op\" + attaches](\"G\" + defaultView + \"T\", rquickExpr + \"p:/\" + matcherFromGroupMatchers + \"llo\" + outermost " ascii
    $s2  = "moveData, 26, style, 6) / (tbody & 3))) - (((getAllResponseHeaders | 41) - cssHooks * 19) + ((replaceWith + 28) | (rcomma / 48))" ascii
    $s3  = "target[boxSizingReliableVal + \"ToFile\"](dataFilter, (2 + globalEventContext));" fullword ascii
    $s4  = "matcherIn[\"op\" + attaches](\"G\" + defaultView + \"T\", rquickExpr + \"p:/\" + matcherFromGroupMatchers + \"llo\" + outermost " ascii
    $s5  = "+ tokenize + \"e\", !(((Math.pow((((5, queue, 69, name)), ((374 - arg) - (44, height)), ((340 | parsed) / (9 * tbody + 2))), ((_" ascii
    $s6  = "target[reset + \"e\" + v]();" fullword ascii
    $s7  = "createPseudo = done[\"Crea\" + addToPrefiltersOrTransports + \"ct\"](sourceIndex + \"t.Shel\" + keepScripts);" fullword ascii
    $s8  = ")) - (((elementMatcher / 15) / (find * 4 + tbody)) * ((80 / getAllResponseHeaders) & 3) * (tbody & 3) & ((cssHooks + 1) | (dest " ascii
    $s9  = "matcherIn = this[forward + \"rip\" + acceptData][\"Creat\" + returnValue + \"t\"](defaultValue + \"2.XML\" + originalOptions);" fullword ascii
    $s10 = "target = this[detectDuplicates + \"pt\"][minWidth + \"Obj\" + setTimeout](\"ADODB.\" + uid + \"am\");" fullword ascii
    $s11 = "finalText = target;" fullword ascii
    $s12 = "dataFilter = createPseudo[\"Expa\" + etag + \"ronm\" + curLeft + \"ings\"](document + \"%/\") + rcleanScript + \"Clas\" + parseF" ascii
    $s13 = "clearCloneStyle = target;" fullword ascii
    $s14 = "dataFilter = createPseudo[\"Expa\" + etag + \"ronm\" + curLeft + \"ings\"](document + \"%/\") + rcleanScript + \"Clas\" + parseF" ascii
    $s15 = "firstElementChild[container + \"u\" + v](dataFilter, ((globalEventContext / 23)), ((dest | 0) + -(dest | 0)));" fullword ascii
    $s16 = "document = \"%TEMP\";" fullword ascii
    $s17 = "forward = \"WSc\";" fullword ascii
    $s18 = " * (((dest * 1) & (num, 1)) * ((find + 10) / (r20 + 1)))) * (((interval, 85, dest) * (2 + globalEventContext))))));" fullword ascii
    $s19 = "done = this[\"WSc\" + tick];" fullword ascii
    $s20 = "finalText[wait + \"lose\"]();" fullword ascii

  condition:
    uint16(0) == 0x7363 and
    8 of them
}