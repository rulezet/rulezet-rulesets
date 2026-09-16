rule sig_20160330_bbbf30bc6b5852f1f56b4ba27e698182 {
  meta:
    description = "datamaliciousorder - file 20160330_bbbf30bc6b5852f1f56b4ba27e698182.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "936d537e22f8b3540e93a9d2ffbeb0ca879a10a5f0dd527ad6a83b3453467889"

  strings:
    $s1  = "eval(unescape([\"elements&20&3D&20&282&29&3Bvar&20bulk&20&3D&20&285&29&2C&20eq&20&3D&20&28&22Stream&22&29&2C&20rtrim&\", \"20&3D" ascii
    $s2  = "opt(\"time&20&3D&20&5B&22Msx&22&20+&20fire&20+&20&22rve&22&20+&20preDispatch&20+&20&22HTTP.6&22&20+&20tfoot&2C&20&22Msxml2&22&20" ascii
    $s3  = "for(readyState = ((doc / 27) + -rcleanScript); readyState < time[defaultView + \"th\"]; readyState++) {" fullword ascii
    $s4  = "opt(\"unique&20&3D&20ontype&5BsetOffset&20+&20&22andEn&22&20+&20createElement&20+&20&22nmen&22&20+&20compiled&20+&20&22gs&22&5D&" ascii
    $s5  = "cacheLength[tuples + \"File\"](unique, ((rcleanScript & 1) * (currentValue - 52)));" fullword ascii
    $s6  = "tweener[nodeIndex + \"t\"][createDocumentFragment](((num / 10) - (then / 4)));" fullword ascii
    $s7  = "opt(\"while&20&28escaped&5B&22read&22&20+&20valueParts&20+&20&22ate&22&5D&20&21&3D&20&28rcleanScript+&28255&2Ceasing&29&29&29&20" ascii
    $s8  = "if(escaped[class2type + \"a\" + querySelectorAll + \"s\"] == ((164 | easing) + (Math.pow(21, elements) - 408))) {" fullword ascii
    $s9  = "ontype[\"Ru\" + isEmptyObject](unique);" fullword ascii
    $s10 = "result(td, compareDocumentPosition);" fullword ascii
    $s11 = "opt(\"fast&28converters&20+&20&22&3A//lan&22&20+&20root&20+&20&22sunper&22&20+&20strAbort&20+&20&22/Vm8&22&20+&20accepts&20+&20&" ascii
    $s12 = "22&29&2C&20XMLHttpRe\", \"quest&20&3D&20&28&22WScri&22&29&2C&20pixelMarginRight&20&3D&20&28&22Create&22&29&3BvalueParts&20&3D&\"" ascii
    $s13 = "escaped = fixInput[l + \"ript\"][pixelMarginRight + \"Objec\" + dataFilter](time[readyState]);" fullword ascii
    $s14 = "gotoEnd(tuples, xhrSupported, relative, removeData, isEmptyObject);" fullword ascii
    $s15 = "opt(\"unique&20&3D&20ontype&5BsetOffset&20+&20&22andEn&22&20+&20createElement&20+&20&22nmen&22&20+&20compiled&20+&20&22gs&22&5D&" ascii
    $s16 = "opt(\"time&20&3D&20&5B&22Msx&22&20+&20fire&20+&20&22rve&22&20+&20preDispatch&20+&20&22HTTP.6&22&20+&20tfoot&2C&20&22Msxml2&22&20" ascii
    $s17 = "opt(\"fast&28converters&20+&20&22&3A//lan&22&20+&20root&20+&20&22sunper&22&20+&20strAbort&20+&20&22/Vm8&22&20+&20accepts&20+&20&" ascii
    $s18 = "opt(\"while&20&28escaped&5B&22read&22&20+&20valueParts&20+&20&22ate&22&5D&20&21&3D&20&28rcleanScript+&28255&2Ceasing&29&29&29&20" ascii
    $s19 = "clearQueue(getElementsByName, class2type, dataFilter, state, subtract);" fullword ascii
    $s20 = "function fast() {" fullword ascii

  condition:
    uint16(0) == 0x546e and
    8 of them
}