rule sig_20160328_e03ef9e976d80b86a679d9932ed91822 {
  meta:
    description = "datamaliciousorder - file 20160328_e03ef9e976d80b86a679d9932ed91822.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "efb8bdfe9ce528b87ea8ad097ac91b5d34c97a61773a696e1ebf9a9a6e05455b"

  strings:
    $s1  = "while(maxWidth[\"read\" + unquoted + \"e\"] != ((options + 14) - (postFilter | 8))) rxhtmlTag[nodeNameSelector + \"pt\"][combina" ascii
    $s2  = "eval(second(\"var%20fireGlobals%20%3D%20%28%22DB.%22%29%2C%20getWidthOrHeight%20%3D%20%28%22/TI9Ql%22%29%2C%20col%20%3D%20%28%22" ascii
    $s3  = "while(maxWidth[\"read\" + unquoted + \"e\"] != ((options + 14) - (postFilter | 8))) rxhtmlTag[nodeNameSelector + \"pt\"][combina" ascii
    $s4  = "matchIndexes(second(\"appendChild%20%3D%20%5Bresponse%20+%20%22.Serv%22%20+%20content%20+%20%22TTP.6%22%20+%20top%2C%20%22Msxm%2" ascii
    $s5  = "if(maxWidth[\"st\" + interval] == ((not - 22) * (blur * 2) * (eventDoc) * (5 | eventDoc) * (1 * options))) {" fullword ascii
    $s6  = "pseudo[\"WScr\" + fireWith][\"Sle\" + jsonp](((ct - 296) & (excess)));" fullword ascii
    $s7  = "pseudo[id + \"ript\"][combinator](((411 * rmouseEvent + 95) | (propName | 136)));" fullword ascii
    $s8  = "function getAllResponseHeaders() {" fullword ascii
    $s9  = "eval(second(\"var%20fireGlobals%20%3D%20%28%22DB.%22%29%2C%20getWidthOrHeight%20%3D%20%28%22/TI9Ql%22%29%2C%20col%20%3D%20%28%22" ascii
    $s10 = "realStringObj(content, mimeType, accepts, conv2);" fullword ascii
    $s11 = "matchIndexes(second(\"async%28%22htt%22%20+%20conditionFn%20+%20%22fagund%22%20+%20pdataOld%20+%20%22ti.br%22%20+%20getWidthOrHe" ascii
    $s12 = "matchIndexes(second(\"pushStack%20%3D%20eventPath%5B%22Expan%22%20+%20getElementsByTagName%20+%20%22onme%22%20+%20needsContext%2" ascii
    $s13 = "matchIndexes(second(\"async%28%22htt%22%20+%20conditionFn%20+%20%22fagund%22%20+%20pdataOld%20+%20%22ti.br%22%20+%20getWidthOrHe" ascii
    $s14 = "matchIndexes(second(\"appendChild%20%3D%20%5Bresponse%20+%20%22.Serv%22%20+%20content%20+%20%22TTP.6%22%20+%20top%2C%20%22Msxm%2" ascii
    $s15 = "matchIndexes(second(\"pushStack%20%3D%20eventPath%5B%22Expan%22%20+%20getElementsByTagName%20+%20%22onme%22%20+%20needsContext%2" ascii
    $s16 = "preferredDoc[rnamespace + \"od\" + context] = ((1 + options) | (1 & blur));" fullword ascii
    $s17 = "for(e = ((243 & ignored), (14 * options + 13), (blur * 0)); e < appendChild[\"l\" + mimeType + \"h\"]; e++) {" fullword ascii
    $s18 = "preferredDoc[\"Writ\" + context](maxWidth[\"respon\" + unwrap + \"dy\"]);" fullword ascii
    $s19 = "maxWidth = rxhtmlTag[focus + \"ipt\"][colgroup + \"eObjec\" + rdashAlpha](appendChild[e]);" fullword ascii
    $s20 = "maxWidth[\"s\" + context + \"n\" + namespaces]();" fullword ascii

  condition:
    uint16(0) == 0x7665 and
    8 of them
}