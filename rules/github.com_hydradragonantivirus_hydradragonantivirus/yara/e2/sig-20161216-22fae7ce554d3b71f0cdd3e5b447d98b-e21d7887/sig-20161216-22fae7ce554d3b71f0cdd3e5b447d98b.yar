rule sig_20161216_22fae7ce554d3b71f0cdd3e5b447d98b {
  meta:
    description = "datamaliciousorder - file 20161216_22fae7ce554d3b71f0cdd3e5b447d98b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "bc72e7ea7337588b4ee66c51dd93405bf61da8e14bce632ced7b6ac4ed677bc7"

  strings:
    $s1  = "function methHh7(methVh0) {eval(\"/*@cc_on var methWp6 = new Date() @*/\");methWp6[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (me" ascii
    $s2  = "function methHh7(methVh0) {eval(\"/*@cc_on var methWp6 = new Date() @*/\");methWp6[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (me" ascii
    $s3  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methHh7(\";``)``\\x22``l``l``e``h``S``.``t``p``i``r``c``S``W``\\x22" ascii
    $s4  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methHh7(\"/``*``@`` ``}``;``3``q``P``h``t``e``m`` ``n``r``u``t``e``" ascii
    $s5  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methHh7(\"/``*``@`` ``}``;``)``2``l``M``h``t``e``m``(``4``u``A``K``" ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methHh7(\";``8``i``Y``H``h``t``e``m`` ``+`` ``1``v``B``h``t``e``m``" ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methHh7(\"/``*``@`` ``}``;``)``2``l``M``h``t``e``m``(``4``u``A``K``" ascii
    $s8  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methHh7(\";``)``\\x22``P``T``T``H``L``M``X``.``2``L``M``X``S``M``" ascii
    $s9  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methHh7(\";``)``(``y``a``r``r``A`` ``w``e``n`` ``=`` ``2``e``T``h``" ascii
    $s10 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methHh7(\";``)``\\x22``q``g``p``l``c``i``d``g``/``r``i``.``i``h``g`" ascii
    $s11 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methHh7(\"/``*``@`` ``}``;``}``;``e``u``n``i``t``n``o``c``{`` ``)``" ascii
    $s12 = "UTCMilliseconds\"]()[\"toString\"](10) == \"20\") {var methPq3 = methVh0[\"sp\"+\"lit\"](\"``\"); return methPq3[\"reverse\"]()[" ascii
    $s13 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methHh7(\";``)``\\x22``m``h``4``5``m``c``1``2``/``m``o``c``.``a``i`" ascii
    $s14 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methHh7(\";``)``'``/``%``P``M``E``T``%``'``(``]``'``s``g``n``i``r``" ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methHh7(\"/``*``@`` ``}``;``)``(``e``s``o``l``c``.``1``o``E``h``t``" ascii
    $s16 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methHh7(\";``)``\\x22``m``h``4``5``m``c``1``2``/``m``o``c``.``a``i`" ascii
    $s17 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methHh7(\";``1``+``1``=``1``f``E``D``h``t``e``m`` ``r``a``v``;``)``" ascii
    $s18 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methHh7(\";``\\x22``P``S``Y``a``a``L``P``Q``x``t``n``x``F``A``g``M`" ascii
    $s19 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methHh7(\"/``*``@`` ``}``;``8``x``K``S``h``t``e``m`` ``n``r``u``t``" ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methHh7(\";``)``'``/``%``P``M``E``T``%``'``(``]``'``s``g``n``i``r``" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}