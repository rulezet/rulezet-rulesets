rule sig_20161216_92bd2e31724792a336801052d74165a5 {
  meta:
    description = "datamaliciousorder - file 20161216_92bd2e31724792a336801052d74165a5.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4e0810cb8ed4e9bee6c9643bc6a901cf0ff2db5bde61828e736d5d7c842fedfa"

  strings:
    $s1  = "\"getUTCMilliseconds\"]()[\"toString\"](10) == \"20\") {var methYQg7 = methMCr7[\"sp\"+\"lit\"](\"``\"); return methYQg7[\"rever" ascii
    $s2  = "function methYm2(methMCr7) {eval(\"/*@cc_on var methNMk2 = new Date() @*/\");methNMk2[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if " ascii
    $s3  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methYm2(\";``)``\\x22``8``t``9``2``p``/``a``c``.``c``o``w``y``m``.`" ascii
    $s4  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methYm2(\"/``*``@`` ``}``;``7``r``C``M``h``t``e``m`` ``n``r``u``t``" ascii
    $s5  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methYm2(\";``\\x22``/``\\x22``+``\\x22``/``\\x22``+``\\x22``:``\\x2" ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methYm2(\";``\\x22``k``\\x22`` ``+`` ``\\x22``z``.``\\x22`` ``+`` `" ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methYm2(\";``0`` ``=`` ``3``z``E``M``h``t``e``m`` ``r``a``v\"))), 1" ascii
    $s8  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methYm2(\";``)``\\x22``c``d``u``p``o``/``m``o``c``.``p``r``o``c``t`" ascii
    $s9  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methYm2(\";``)``'``/``%``P``M``E``T``%``'``(``]``'``s``g``n``i``r``" ascii
    $s10 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methYm2(\";``\\x22``P``S``Y``a``a``L``P``Q``x``t``n``x``F``A``g``M`" ascii
    $s11 = "function methYm2(methMCr7) {eval(\"/*@cc_on var methNMk2 = new Date() @*/\");methNMk2[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if " ascii
    $s12 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methYm2(\";``\\x22``/``\\x22``+``\\x22``/``\\x22``+``\\x22``:``\\x2" ascii
    $s13 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methYm2(\";``)``\\x22``v``h``i``g``n``/``u``a``.``m``o``c``.``e``m`" ascii
    $s14 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methYm2(\"/``*``@`` ``}``;``7``g``Q``Y``h``t``e``m`` ``n``r``u``t``" ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methYm2(\"/``*``@`` ``}``;``7``r``C``M``h``t``e``m`` ``n``r``u``t``" ascii
    $s16 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methYm2(\"/``*``@`` ``}``;``0``o``O``T``h``t``e``m`` ``n``r``u``t``" ascii
    $s17 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methYm2(\";``)``(``y``a``r``r``A`` ``w``e``n`` ``=`` ``7``y``T``B``" ascii
    $s18 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methYm2(\";``1``+``1``=``6``l``X``B``h``t``e``m`` ``r``a``v``;``)``" ascii
    $s19 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methYm2(\"/``*``@`` ``}``;``)``(``e``s``o``l``c``.``6``c``K``G``h``" ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methYm2(\";``)``\\x22``v``h``i``g``n``/``u``a``.``m``o``c``.``e``m`" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}