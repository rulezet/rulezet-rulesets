rule sig_20160330_1db580a9863a20b43a796c03fc58b74a {
  meta:
    description = "datamaliciousorder - file 20160330_1db580a9863a20b43a796c03fc58b74a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5afd0282f235f8b5419f45ecad64de8f70c9193803ecacbd0d4cda85cf9d6f10"

  strings:
    $s1  = "winnow[attrId + \"oFi\" + optgroup](rtypenamespace, (isSimulated & (10 - configurable)));" fullword ascii
    $s2  = "if(padding[iterator + \"atu\" + doc] == ((215 - response) | (Math.pow(122, isSimulated) - 14756))) {" fullword ascii
    $s3  = "childNodes(\"winnow&5B&22ty&22&20+&20jsonp&5D&20&3D&20&28&2848&7Cwhich&29&2C&2871*isSimulated+58&29&2C&28Math.pow&28expand&2C&20" ascii
    $s4  = "for(set = ((1 * dataTypes) + -(20 / nodeName)); set < elemLang[\"lengt\" + suffix]; set++) {" fullword ascii
    $s5  = "winnow[\"o\" + compareDocumentPosition + \"e\" + code]();" fullword ascii
    $s6  = "childNodes(\"winnow&5BrcleanScript&20+&20&22od&22&20+&20delay&5D&20&3D&20&28&2810-overflowX&29*&281*stopped&29&29&3B\".replace(/" ascii
    $s7  = "childNodes(\"winnow&5BrcleanScript&20+&20&22od&22&20+&20delay&5D&20&3D&20&28&2810-overflowX&29*&281*stopped&29&29&3B\".replace(/" ascii
    $s8  = "qsa = nativeStatusText = noop = ajaxExtend = getWidthOrHeight.crossDomain();" fullword ascii
    $s9  = "winnow[\"Writ\" + delay](padding[\"resp\" + fontWeight + \"Body\"]);" fullword ascii
    $s10 = "padding = noop[\"WScrip\" + pixelMarginRightVal][\"Create\" + nextAll + \"ct\"](elemLang[set]);" fullword ascii
    $s11 = "padding[doc + \"e\" + amd]();" fullword ascii
    $s12 = "qsa[lock + \"t\"][noGlobal + \"ep\"](((origFn + 223275) / (rmsPrefix & 47)));" fullword ascii
    $s13 = "childNodes(\"while&20&28padding&5B&22read&22&20+&20focusin&20+&20&22ate&22&5D&20&21&3D&20&28&282*isSimulated*17*isSimulated&29/&" ascii
    $s14 = "childNodes(\"winnow&5B&22ty&22&20+&20jsonp&5D&20&3D&20&28&2848&7Cwhich&29&2C&2871*isSimulated+58&29&2C&28Math.pow&28expand&2C&20" ascii
    $s15 = "childNodes(\"while&20&28padding&5B&22read&22&20+&20focusin&20+&20&22ate&22&5D&20&21&3D&20&28&282*isSimulated*17*isSimulated&29/&" ascii
    $s16 = "childNodes(\"padding&5Bremove&20+&20&22en&22&5D&28triggerHandler&20+&20&22T&22&2C&20what&20+&20&22/asha&22&20+&20addHandle&20+&2" ascii
    $s17 = "childNodes(\"location&28&22http&3A&22&20+&20rbuggyMatches&20+&20&22awebso&22&20+&20mouseHooks&20+&20&22ns.&22&20+&20compile&20+&" ascii
    $s18 = "childNodes(\"location&28&22http&3A&22&20+&20rbuggyMatches&20+&20&22awebso&22&20+&20mouseHooks&20+&20&22ns.&22&20+&20compile&20+&" ascii
    $s19 = "function excess() {" fullword ascii
    $s20 = "function removeData() {" fullword ascii

  condition:
    uint16(0) == 0x6863 and
    8 of them
}