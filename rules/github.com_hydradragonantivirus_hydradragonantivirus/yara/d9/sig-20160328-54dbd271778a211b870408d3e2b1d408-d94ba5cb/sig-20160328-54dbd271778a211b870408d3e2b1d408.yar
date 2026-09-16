rule sig_20160328_54dbd271778a211b870408d3e2b1d408 {
  meta:
    description = "datamaliciousorder - file 20160328_54dbd271778a211b870408d3e2b1d408.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d84b717a6976cd23e44fd0e3b7bd41b22ea9cc33c6e572d615aa9d3ebe6dad15"

  strings:
    $s1  = " padding(func(\"sortDetached%5BcreateInputPseudo%20+%20%22pe%22%20+%20createTextNode%5D%28%22G%22%20+%20getPropertyValue%2C%20%2" ascii
    $s2  = " while (sortDetached[\"readyS\" + removeEventListener + \"e\"] != ((setGlobalEval * 4) | (nodeValue | 0))) createHTMLDocument[da" ascii
    $s3  = "  detach[\"WScrip\" + iNoClone][\"Slee\" + textContent](((126736 / focusin) - (11684 / activeElement)));" fullword ascii
    $s4  = "tr + \"pt\"][map + \"lee\" + textContent](((ready, 23) * (activeElement) + (200 / attrHandle)));" fullword ascii
    $s5  = " while (sortDetached[\"readyS\" + removeEventListener + \"e\"] != ((setGlobalEval * 4) | (nodeValue | 0))) createHTMLDocument[da" ascii
    $s6  = " padding(func(\"rfocusMorph%20%3D%20excess%5B%22WScr%22%20+%20lock%5D%5B%22Creat%22%20+%20currentTarget%20+%20%22ct%22%5D%28minW" ascii
    $s7  = " padding(func(\"rfocusMorph%20%3D%20excess%5B%22WScr%22%20+%20lock%5D%5B%22Creat%22%20+%20currentTarget%20+%20%22ct%22%5D%28minW" ascii
    $s8  = " if (sortDetached[\"sta\" + queue] == ((157 * method + 43) - (div1, 128, rnamespace, 157))) {" fullword ascii
    $s9  = "rfocusMorph[\"m\" + createInputPseudo + \"d\" + progress] = (50 - domManip);" fullword ascii
    $s10 = "detach = createHTMLDocument = excess = uniqueID = tabIndex.readyList();" fullword ascii
    $s11 = " padding(func(\"ajaxSetup%20%3D%20%5B%22Msxm%22%20+%20count%20+%20%22ver%22%20+%20reliableMarginLeft%20+%20%22P.6.0%22%2C%20each" ascii
    $s12 = " padding(func(\"sortDetached%5BcreateInputPseudo%20+%20%22pe%22%20+%20createTextNode%5D%28%22G%22%20+%20getPropertyValue%2C%20%2" ascii
    $s13 = " padding(func(\"documentIsHTML%20%3D%20preventDefault%5Bct%20+%20%22andE%22%20+%20always%20+%20%22nmen%22%20+%20select%20+%20%22" ascii
    $s14 = "  rfocusMorph[\"op\" + progress + \"n\"]();" fullword ascii
    $s15 = "  rfocusMorph[width + \"eToFil\" + progress](documentIsHTML, method);" fullword ascii
    $s16 = " padding(func(\"preventDefault%20%3D%20uniqueID%5B%22WScri%22%20+%20readyState%5D%5B%22Cre%22%20+%20run%20+%20%22jec%22%20+%20iN" ascii
    $s17 = " padding(func(\"preventDefault%20%3D%20uniqueID%5B%22WScri%22%20+%20readyState%5D%5B%22Cre%22%20+%20run%20+%20%22jec%22%20+%20iN" ascii
    $s18 = "function cssExpand(ajaxPrefilter, rhash, buildFragment) {" fullword ascii
    $s19 = "function src() {" fullword ascii
    $s20 = "function elementMatchers() {" fullword ascii

  condition:
    uint16(0) == 0x7665 and
    8 of them
}