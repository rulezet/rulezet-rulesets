rule sig_20160311_cad50fb0697c2c0438f5d16641fc15ab {
  meta:
    description = "datamaliciousorder - file 20160311_cad50fb0697c2c0438f5d16641fc15ab.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "11e8df42ed046221c90d81b93daeb46dd209abe35dee9048218f9f1ebd5275fd"

  strings:
    $s1  = "setDocument[\"op\" + rinputs + \"n\".opts()](postDispatch + \"ET\", deepDataAndEvents + \"//g\" + fast + \"aw.co.\".opts() + mar" ascii
    $s2  = "getPropertyValue[\"t\".opts() + tween + \"e\"] = ((Math.pow(20, elements) - 378) - (currentTime / 34));" fullword ascii
    $s3  = "ing) - (4 | rnotwhite)), ((29 + pointerleave), (Math.pow(22, elements) - 444), (xhrFields | 70), identifier));" fullword ascii
    $s4  = " (reverse / 22)) - (rtagName * 2)) / (Math.pow((Math.pow((pageY & 7), (elements + 0)) - (tweener / 1)), (version - 48)) - (Math." ascii
    $s5  = "eXML / (3, rjsonp, 125, parseXML))) + (((3 + identifier) + 2 * elements) & (5 * fadeOut / (19 - offsetWidth))))));" fullword ascii
    $s6  = "\"32tg\" + matcherOut, !((((Math.pow((24451 / cacheLength), (31 - ajaxPrefilter)) - (452229 - init)) / ((16 | identifier) & (Mat" ascii
    $s7  = "setDocument = t[multipleContexts + \"ipt\"][clearTimeout + \"teObj\" + rcleanScript](\"MSX\".opts() + throws + \"XMLHTT\" + tick" ascii
    $s8  = "parent[\"R\".opts() + cacheURL](cos.opts(((4 * elements + 3) * (identifier | 8) + (rtagName & 1))), ((Math.pow(useCache, 2) - pa" ascii
    $s9  = "parent[\"R\".opts() + cacheURL](cos.opts(((4 * elements + 3) * (identifier | 8) + (rtagName & 1))), ((Math.pow(useCache, 2) - pa" ascii
    $s10 = "setDocument[\"op\" + rinputs + \"n\".opts()](postDispatch + \"ET\", deepDataAndEvents + \"//g\" + fast + \"aw.co.\".opts() + mar" ascii
    $s11 = "pow(12, elements) - 121))) - (((rtagName & 1) & (rtagName | 0)) * ((elements + 4) + (outermostContext | 0)))) * ((((once - 71) |" ascii
    $s12 = "pow((clearQueue - 83), (identifier | 2)) - (camelCase, 182, image)))) == ((((180, valueIsBorderBox, 1) + identifier) * (2 * pars" ascii
    $s13 = "cos = createInputPseudo[\"Exp\" + pseudo + \"Envi\".opts() + addToPrefiltersOrTransports + \"entS\" + eased](\"%TEM\" + scrollTo" ascii
    $s14 = "function tabIndex() {" fullword ascii
    $s15 = "identifier = 0, image = 1887;" fullword ascii
    $s16 = "cos = createInputPseudo[\"Exp\" + pseudo + \"Envi\".opts() + addToPrefiltersOrTransports + \"entS\" + eased](\"%TEM\" + scrollTo" ascii
    $s17 = "version = 50;" fullword ascii
    $s18 = "function raw() {" fullword ascii
    $s19 = "function cssHooks() {" fullword ascii
    $s20 = "tick = \"P\";" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}