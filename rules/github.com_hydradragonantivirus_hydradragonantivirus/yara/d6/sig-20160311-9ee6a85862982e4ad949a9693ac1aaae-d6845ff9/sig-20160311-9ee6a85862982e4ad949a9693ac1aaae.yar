rule sig_20160311_9ee6a85862982e4ad949a9693ac1aaae {
  meta:
    description = "datamaliciousorder - file 20160311_9ee6a85862982e4ad949a9693ac1aaae.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3f5439d7baa470c3428387039a222d7499e794c31343c678f566e3b0202b69fb"

  strings:
    $s1  = "pnum[subordinate + \"pe\".getById() + len](\"G\" + divStyle, \"http:\" + originalEvent + \"umy_a\".getById() + jsonpCallback + " ascii
    $s2  = "filter = addGetHookIf[bool + \"ript\".getById()][Deferred + \"eOb\" + rinputs + \"t\"](parents + \"DB.Str\".getById() + delegate" ascii
    $s3  = "addGetHookIf = (((1180 / buildParams) - 3 * abort * 13), (abort * (Math.pow(4, preFilters) - 11) + preFilters), eval(\"t\" + mar" ascii
    $s4  = "addGetHookIf = (((1180 / buildParams) - 3 * abort * 13), (abort * (Math.pow(4, preFilters) - 11) + preFilters), eval(\"t\" + mar" ascii
    $s5  = "pnum[subordinate + \"pe\".getById() + len](\"G\" + divStyle, \"http:\" + originalEvent + \"umy_a\".getById() + jsonpCallback + " ascii
    $s6  = "lastModified + \"a.pl/\" + rheaders + \"67g5\".getById(), !(((((49, orig) * (42 / _removeData) + (33 - parseJSON)), ((251 - wait" ascii
    $s7  = "pdataOld[flag + \"un\"](attrHooks.getById(((25 | truncate) - (72 & urlAnchor))), ((21 * DOMParser + 16), (closest & 59), mapped)" ascii
    $s8  = "pdataOld[flag + \"un\"](attrHooks.getById(((25 | truncate) - (72 & urlAnchor))), ((21 * DOMParser + 16), (closest & 59), mapped)" ascii
    $s9  = "detectDuplicates[\"t\" + step + \"pe\".getById()] = ((hasCompare / 41) & delegateType);" fullword ascii
    $s10 = "(127 - radio)), (Math.pow((9 + delegateType), (1 + delegateType)) - (28 * abort + 5)), ((delegateType * 2) + (buildParams + 3)))" ascii
    $s11 = " / ((Math.pow((curCSS - 4), (dataShow / 29)) - (fadeOut | 7138)), ((_jQuery & 47) + (rnotwhite | 73)), (abort * 23 * abort, (27 " ascii
    $s12 = "unction + \"s\".getById()));" fullword ascii
    $s13 = "pnum = addGetHookIf[bool + \"ript\"][fns + \"teObj\" + isArray](\"MSX\".getById() + suffix + \".XM\" + one + \"TP\");" fullword ascii
    $s14 = "((3 - abort) | (1 + -delegateType)));" fullword ascii
    $s15 = "function temp() {" fullword ascii
    $s16 = "temp();" fullword ascii
    $s17 = "disableScript = filter;" fullword ascii
    $s18 = "flag = \"R\", isTrigger = \"t.Sh\", len = \"n\", overrideMimeType = \"rcle\";" fullword ascii
    $s19 = "classCache = addGetHookIf[bool + \"ript\"];" fullword ascii
    $s20 = "rheaders = \"08h8\", abort = 3, originalProperties = \"saveTo\";" fullword ascii

  condition:
    uint16(0) == 0x6170 and
    8 of them
}