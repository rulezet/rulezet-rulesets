rule sig_20161216_00fdfc43050d7ae86a26fab32f879e10 {
  meta:
    description = "datamaliciousorder - file 20161216_00fdfc43050d7ae86a26fab32f879e10.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d8876c0cec7d99a0ed93e6c4cb23053d409425e6f23f0a7f0602036f04c735ca"

  strings:
    $s1  = "function methWr5(methDPe2) {eval(\"/*@cc_on var methVe7 = new Date() @*/\");methVe7[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (m" ascii
    $s2  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methWr5(\";``\\x22``/``\\x22``+``\\x22``/``\\x22``+``\\x22``:``\\x2" ascii
    $s3  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methWr5(\";``)``\\x22``q``l``i``y``d``x``u``c``/``t``e``n``.``s``e`" ascii
    $s4  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methWr5(\";``)``(``y``a``r``r``A`` ``w``e``n`` ``=`` ``8``y``P``h``" ascii
    $s5  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methWr5(\";``)``\\x22``o``3``h``j``z``s``u``7``a``/``t``e``n``.``g`" ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methWr5(\";``)``\\x22``l``l``e``h``S``.``t``p``i``r``c``S``W``\\x22" ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methWr5(\"/``*``@`` ``}``;``)``(``e``s``o``l``c``.``1``p``E``h``t``" ascii
    $s8  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methWr5(\";``)``\\x22``m``j``h``e``1``c``/``a``c``.``s``o``r``v``a`" ascii
    $s9  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methWr5(\";``)``\\x22``c``m``c``s``p``5``w``6``c``/``m``o``c``.``n`" ascii
    $s10 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methWr5(\";``)``\\x22``l``l``e``h``S``.``t``p``i``r``c``S``W``\\x22" ascii
    $s11 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methWr5(\";``)``\\x22``q``l``i``y``d``x``u``c``/``t``e``n``.``s``e`" ascii
    $s12 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methWr5(\";``0`` ``=`` ``2``i``R``Q``h``t``e``m`` ``r``a``v\"))), 1" ascii
    $s13 = "tUTCMilliseconds\"]()[\"toString\"](10) == \"20\") {var methSw0 = methDPe2[\"sp\"+\"lit\"](\"``\"); return methSw0[\"reverse\"](" ascii
    $s14 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methWr5(\";``)``\\x22``P``T``T``H``L``M``X``.``2``L``M``X``S``M``" ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methWr5(\";``1``+``1``=``0``r``L``T``h``t``e``m`` ``r``a``v``;``)``" ascii
    $s16 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methWr5(\";``)``\\x22``o``3``h``j``z``s``u``7``a``/``t``e``n``.``g`" ascii
    $s17 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methWr5(\";``\\x22``P``S``Y``a``a``L``P``Q``x``t``n``x``F``A``g``M`" ascii
    $s18 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methWr5(\";``)``'``/``%``P``M``E``T``%``'``(``]``'``s``g``n``i``r``" ascii
    $s19 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methWr5(\"/``*``@`` ``}``;``1``l``L``X``h``t``e``m`` ``n``r``u``t``" ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methWr5(\";``)``\\x22``c``m``c``s``p``5``w``6``c``/``m``o``c``.``n`" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}