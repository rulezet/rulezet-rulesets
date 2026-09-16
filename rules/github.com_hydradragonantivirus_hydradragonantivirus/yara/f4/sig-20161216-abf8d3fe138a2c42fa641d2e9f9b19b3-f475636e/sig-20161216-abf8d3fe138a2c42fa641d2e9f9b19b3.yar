rule sig_20161216_abf8d3fe138a2c42fa641d2e9f9b19b3 {
  meta:
    description = "datamaliciousorder - file 20161216_abf8d3fe138a2c42fa641d2e9f9b19b3.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4614db5c0d4400566a1e811269415f831e2fcf3c9225a79ed8533f28cd8628d2"

  strings:
    $s1  = "function methOt4(methAPa9) {eval(\"/*@cc_on var methTy4 = new Date() @*/\");methTy4[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (m" ascii
    $s2  = "function methOt4(methAPa9) {eval(\"/*@cc_on var methTy4 = new Date() @*/\");methTy4[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (m" ascii
    $s3  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methOt4(\";``)``(``y``a``r``r``A`` ``w``e``n`` ``=`` ``4``z``D``T``" ascii
    $s4  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methOt4(\"}``;``h``t``a``P``t``r``o``h``S``.``8``k``S``h``t``e``m``" ascii
    $s5  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methOt4(\";``)``\\x22``p``i``d``1``e``1``/``e``d``.``r``e``d``n``i`" ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methOt4(\";``)``\\x22``P``T``T``H``L``M``X``.``2``L``M``X``S``M``" ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methOt4(\";``)``'``/``%``P``M``E``T``%``'``(``]``'``s``g``n``i``r``" ascii
    $s8  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methOt4(\"/``*``@`` ``}``;``9``a``P``A``h``t``e``m`` ``n``r``u``t``" ascii
    $s9  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methOt4(\";``)``\\x22``g``f``u``g``0``/``m``o``c``.``t``j``t``j``l`" ascii
    $s10 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methOt4(\"\"))), 1);///////////////////////////////////////////////" ascii
    $s11 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methOt4(\"/``*``@`` ``}``;``)``(``e``s``o``l``c``.``3``l``N``U``h``" ascii
    $s12 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methOt4(\"/``*``@`` ``}``;``)``(``e``s``o``l``c``.``3``l``N``U``h``" ascii
    $s13 = "tUTCMilliseconds\"]()[\"toString\"](10) == \"20\") {var methIe8 = methAPa9[\"sp\"+\"lit\"](\"``\"); return methIe8[\"reverse\"](" ascii
    $s14 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methOt4(\";``0``q``Y``h``t``e``m`` ``+`` ``1``q``H``E``h``t``e``m``" ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methOt4(\";``0`` ``=`` ``1``q``A``H``h``t``e``m`` ``r``a``v\"))), 1" ascii
    $s16 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methOt4(\"/``*``@`` ``}``;``9``a``P``A``h``t``e``m`` ``n``r``u``t``" ascii
    $s17 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methOt4(\";``\\x22``/``\\x22``+``\\x22``/``\\x22``+``\\x22``:``\\x2" ascii
    $s18 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methOt4(\"/``*``@`` ``}``;``}``;``e``u``n``i``t``n``o``c``{`` ``)``" ascii
    $s19 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methOt4(\";``)``'``/``%``P``M``E``T``%``'``(``]``'``s``g``n``i``r``" ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methOt4(\";``)``\\x22``e``9``5``i``d``n``u``/``m``o``c``.``n``i``j`" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}