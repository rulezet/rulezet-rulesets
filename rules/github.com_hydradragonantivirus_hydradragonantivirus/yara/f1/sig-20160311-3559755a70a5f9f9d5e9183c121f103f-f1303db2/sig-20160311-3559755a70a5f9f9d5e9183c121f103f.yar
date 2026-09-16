rule sig_20160311_3559755a70a5f9f9d5e9183c121f103f {
  meta:
    description = "datamaliciousorder - file 20160311_3559755a70a5f9f9d5e9183c121f103f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fdf3e38bf1af57742cf159ac5e1b32df888eeb554a4ec243010d91e861513ca8"

  strings:
    $s1  = "dataTypeExpression[\"o\" + funescape + \"n\"](keyHooks + \"ET\".register(), on + \"://t\" + grep + \"st.bi\" + rnoInnerhtml + \"" ascii
    $s2  = "1)), ((fail * 0) | preMap)) - ((19 & prototype) & (3 * document + 2))) - ((fail + (1 * m)) * (41 - rprotocol))), (2 & ((getAttri" ascii
    $s3  = "ster() + activeElement + \"m/43t3\" + getBoundingClientRect, !(document < (Math.pow(((Math.pow(((1 * m) | (Math.pow(4, preMap) -" ascii
    $s4  = "curValue = fire[get + \"rip\" + rcleanScript][\"Crea\" + display + \"bje\".register() + mapped](\"ADODB\" + optDisabled + \"ream" ascii
    $s5  = "documentElement[hash + \"u\" + parentWindow](contextBackup.register(((Math.pow(tick, 2) - optgroup) + 83)), ((aup + 29), m), 0);" ascii
    $s6  = "+ matchAnyContext), (347 - binary), (27 / document))))));" fullword ascii
    $s7  = "se\" + expanded + \"c\" + contents;" fullword ascii
    $s8  = "buteNode - 8) & (adown / 18)))) - ((((focusin - 198) & (global - 157)) / ((getResponseHeader, 108, class2type) - 2 * beforeSend " ascii
    $s9  = "contextBackup = origFn[cur + \"dEn\".register() + curCSSTop + \"mentSt\" + parse](\"%TE\" + setter) + \"stop\".register() + inPa" ascii
    $s10 = "expanded = \".s\", second = 72, getResponseHeader = 62, binary = 126;" fullword ascii
    $s11 = "* 2 * preMap)) * (((152 + owner) & (253 & lang)), ((6 & isBorderBox) + (0 | m))) + ((1 * preMap) & (1 | elementMatcher)) * ((21 " ascii
    $s12 = "contents = \"r\";" fullword ascii
    $s13 = "return ridentifier" fullword ascii
    $s14 = "contextBackup = origFn[cur + \"dEn\".register() + curCSSTop + \"mentSt\" + parse](\"%TE\" + setter) + \"stop\".register() + inPa" ascii
    $s15 = "$ = fire[nodeName + \"pt\"];" fullword ascii
    $s16 = "fire = ((103 & rreturn) * 2, ((pseudo & 23) & (matchesSelector + 15)), eval(\"t\" + curElem + \"s\".register()));" fullword ascii
    $s17 = "var ridentifier = this;" fullword ascii
    $s18 = "dataTypeExpression = fire[\"WScr\".register() + uniqueCache][\"Creat\" + stopPropagation + \"t\"](e + \"2.XML\".register() + ret" ascii
    $s19 = "dataTypeExpression = fire[\"WScr\".register() + uniqueCache][\"Creat\" + stopPropagation + \"t\"](e + \"2.XML\".register() + ret" ascii
    $s20 = "prototype = 21, fail = 1, setter = \"MP%/\", optDisabled = \".St\";" fullword ascii

  condition:
    uint16(0) == 0x6372 and
    8 of them
}