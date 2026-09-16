rule sig_20160311_f8c8ecbde1bab8feab436ae13fb6670c {
  meta:
    description = "datamaliciousorder - file 20160311_f8c8ecbde1bab8feab436ae13fb6670c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5a5039c28f292eefeecd51d3d2fafaff6494e2f61625808f232d329bf8ec3ba6"

  strings:
    $x1  = "charCode = clientX[head + \"andE\" + preventDefault + \"ronm\".defaultDisplay() + finalValue + \"tri\" + random](\"%TEMP%\" + ge" ascii
    $s2  = "charCode = clientX[head + \"andE\" + preventDefault + \"ronm\".defaultDisplay() + finalValue + \"tri\" + random](\"%TEMP%\" + ge" ascii
    $s3  = "conv[getResponseHeader + \"pe\"] = ((submit * 2 + visible), (105 & DOMParser), (2016 / getStyles), (28 - iframe));" fullword ascii
    $s4  = "* 4 + visible) - (9 * visible + 8))) & (((Math.pow(td, 2) - parseXML), (86 - matchExpr), (894 / isDefaultPrevented)), (3 * (lnam" ascii
    $s5  = "ifModified[getById + \"e\" + preferredDoc](\"G\".defaultDisplay() + docElem, \"http\" + mouseleave + \"ter\" + charset + \"kem.c" ascii
    $s6  = "ifModified = relatedTarget[\"WSc\".defaultDisplay() + get][\"Create\" + name + \"ct\"](handlers + \"2.XM\".defaultDisplay() + ha" ascii
    $s7  = "ifModified = relatedTarget[\"WSc\".defaultDisplay() + get][\"Create\" + name + \"ct\"](handlers + \"2.XM\".defaultDisplay() + ha" ascii
    $s8  = "clientX = ajaxTransport[nodeNameSelector + \"Objec\" + postFilter](\"WScrip\".defaultDisplay() + suffix + \"ll\");" fullword ascii
    $s9  = "))), (interval | (1 + -rnative)), ((88, createInputPseudo, 27) - (Math.pow(submit, 2) - hasFocus)));" fullword ascii
    $s10 = "getScript = (function Object.prototype.defaultDisplay() {" fullword ascii
    $s11 = "contentDocument = \"r\", DOMParser = 125, random = \"ngs\", postFilter = \"t\";" fullword ascii
    $s12 = " + \"defaul\".defaultDisplay() + checkOn + \"lue\" + high + \"sc\" + contentDocument;" fullword ascii
    $s13 = "calculatePosition[\"Ru\".defaultDisplay() + preferredDoc](charCode.defaultDisplay(((funescape * 46 + rnative) & (34 * visible + " ascii
    $s14 = "Display() + hasClass + \"745\" + reverse, !((((((visible | 0) + (val - 58)) - funescape) + ((Math.pow((6 & isDefaultPrevented), " ascii
    $s15 = "val)) + -((Math.pow(98, funescape) - 9426), (define - 51), (attrHooks / 38), (interval | 1)))))));" fullword ascii
    $s16 = "contents = \"on\";" fullword ascii
    $s17 = "head = \"Exp\";" fullword ascii
    $s18 = "e - 39))))) == ((((rnative * 1) | funescape * 2)) * ((rnative + 1) & (visible + 0)) + (((submit - 23) * (finalDataType - 38) * v" ascii
    $s19 = "suffix = \"t.She\"," fullword ascii
    $s20 = "return dataTypeOrTransport" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    1 of ($x*) and 4 of them
}