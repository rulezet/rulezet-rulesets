rule sig_20160311_9b313a68bf2a2f0d4b0418e50dcbce5b {
  meta:
    description = "datamaliciousorder - file 20160311_9b313a68bf2a2f0d4b0418e50dcbce5b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c367495b29dd798d25bd28ae3e4b7045cb94f33c1f8903e038c1cda4eb574664"

  strings:
    $x1  = "rkeyEvent[\"op\".factory() + removeAttr](\"G\" + parentsUntil, \"http\" + radioValue + \"peter\".factory() + nodeName + \"em.co" ascii
    $s2  = "rkeyEvent = pseudo[\"WSc\" + thead][\"Cre\".factory() + returnTrue + \"ect\"](includeWidth + \"2.XML\" + delegateType);" fullword ascii
    $s3  = " ((diff, 109, onload) - (55 & parts))) & (((1 * xhrSupported) | (7 + booleans)) - ((Math.pow(4, attributes) - 11) + (truncate - " ascii
    $s4  = "tributes)), ((((0 / compiled) & 1) | ((deep & 1) * (getAllResponseHeaders, 1))) | ((attributes * 8), (document), (2 | attributes" ascii
    $s5  = "lastModified = content[filter + \"dEn\" + fire + \"onmen\".factory() + hash + \"gs\"](offset + \"%/\") + finalDataType + \"ite\"" ascii
    $s6  = "lastModified = content[filter + \"dEn\" + fire + \"onmen\".factory() + hash + \"gs\"](offset + \"%/\") + finalDataType + \"ite\"" ascii
    $s7  = "dequeue[\"Ru\".factory() + props](lastModified.factory(((booleans * 3) | (rbracket + 35))), ((document, 204, xhrSupported) | 0)," ascii
    $s8  = "pseudo = ((1 * booleans) * (37 - identifier), ((68 | nextUntil) - (81 - compile)), eval(\"t\" + capName + \"s\".factory()));" fullword ascii
    $s9  = "content = slideToggle[forward + \"ateObj\" + needsContext](\"WScrip\".factory() + fn + \"l\");" fullword ascii
    $s10 = "s + 5) - (nType / 2))) * ((deep / 1) * (deep * (12 / rdashAlpha))) * (((32 - div)) | ((1 * deep) * (1 * attributes))) * ((1 * at" ascii
    $s11 = "deep + -1));" fullword ascii
    $s12 = "offset = \"%TEMP\";" fullword ascii
    $s13 = "cher + \"7745g\", !(((((1 * rdashAlpha) * (1 + deep) + (Math.pow(3, attributes) - 5)), ((event + 0) | (fixInput & 241)), ((outer" ascii
    $s14 = "28)))) + (((adjustCSS + 250) / (crossDomain | 9)) / ((xhrSupported | 147) / (booleans * 2 + deep))))));" fullword ascii
    $s15 = "dequeue[\"Ru\".factory() + props](lastModified.factory(((booleans * 3) | (rbracket + 35))), ((document, 204, xhrSupported) | 0)," ascii
    $s16 = "letterSpacing = \"Strea\", getAllResponseHeaders = 232, capName = \"hi\", thead = \"ript\", forward = \"Cre\";" fullword ascii
    $s17 = "dequeue = content;" fullword ascii
    $s18 = "doScroll[lang + \"e\" + props]();" fullword ascii
    $s19 = "slideToggle = pseudo[uid + \"ipt\"];" fullword ascii
    $s20 = "doScroll = pseudo[\"WScri\" + ontype][\"Create\" + qualifier](\"ADODB.\".factory() + letterSpacing + \"m\");" fullword ascii

  condition:
    uint16(0) == 0x6e66 and
    1 of ($x*) and 4 of them
}