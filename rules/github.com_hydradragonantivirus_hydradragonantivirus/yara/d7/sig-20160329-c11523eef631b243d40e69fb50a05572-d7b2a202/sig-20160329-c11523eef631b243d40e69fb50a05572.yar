rule sig_20160329_c11523eef631b243d40e69fb50a05572 {
  meta:
    description = "datamaliciousorder - file 20160329_c11523eef631b243d40e69fb50a05572.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "12494f120207842bfb9f9d029dc952defb92f6cf28e6b3472909612f456350e8"

  strings:
    $s1  = "for (fireWith = ((Math.pow(35, handler) - 1178) - (PI, 47)); fireWith < addGetHookIf[\"l\" + swing + \"n\" + view]; fireWith++) " ascii
    $s2  = "dataType(\"duration%5Bcode%20+%20%22e%22%20+%20uniqueSort%5D%28%22GE%22%20+%20getScript%2C%20%22http%22%20+%20includeWidth%20+%2" ascii
    $s3  = "dataType(\"duration%5Bcode%20+%20%22e%22%20+%20uniqueSort%5D%28%22GE%22%20+%20getScript%2C%20%22http%22%20+%20includeWidth%20+%2" ascii
    $s4  = "duration = iNoClone[\"WScr\" + onreadystatechange][\"Creat\" + amd + \"ect\"](addGetHookIf[fireWith]);" fullword ascii
    $s5  = "restoreScript = first = iNoClone = getBoundingClientRect = pushStack.jQuery();" fullword ascii
    $s6  = "if (duration[\"status\"] == (Math.pow((87 * handler + 7), (hookFn * 2)) - (setFilters))) {" fullword ascii
    $s7  = "createInputPseudo[selector + \"y\" + ignored + \"e\"] = (14 - trim);" fullword ascii
    $s8  = "createInputPseudo[appendTo + \"ToFil\" + swing](inspectPrefiltersOrTransports, ((handler | 0)));" fullword ascii
    $s9  = "temp = 285;" fullword ascii
    $s10 = "event[\"R\" + statusCode](inspectPrefiltersOrTransports);" fullword ascii
    $s11 = "dataType(\"while%20%28duration%5BcreatePseudo%20+%20%22tat%22%20+%20swing%5D%20%21%3D%20%28%282*prefilterOrFactory%29-%2810%7Cha" ascii
    $s12 = "function attributes(getElementById) {" fullword ascii
    $s13 = "createInputPseudo[\"Write\"](duration[fireGlobals + \"ons\" + docElem]);" fullword ascii
    $s14 = "duration[\"s\" + diff + \"d\"]();" fullword ascii
    $s15 = "function valHooks(tween, ready) {" fullword ascii
    $s16 = "dataType(\"event%20%3D%20restoreScript%5B%22WScrip%22%20+%20selector%5D%5B%22Create%22%20+%20outerCache%20+%20%22ect%22%5D%28tri" ascii
    $s17 = "dataType(\"event%20%3D%20restoreScript%5B%22WScrip%22%20+%20selector%5D%5B%22Create%22%20+%20outerCache%20+%20%22ect%22%5D%28tri" ascii
    $s18 = "function stopQueue() {" fullword ascii
    $s19 = "function triggered() {" fullword ascii
    $s20 = "function name() {" fullword ascii

  condition:
    uint16(0) == 0x6574 and
    8 of them
}