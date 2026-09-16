rule sig_20161216_771091b04cbe70eacf6fc03a81574a52 {
  meta:
    description = "datamaliciousorder - file 20161216_771091b04cbe70eacf6fc03a81574a52.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "653b69b49964ca321b0fdfd58246e30ab53e4ecd802875a3b5ffd0266f11b930"

  strings:
    $s1  = "function methPx0(methJZz8) {eval(\"/*@cc_on var methBCh3 = new Date() @*/\");methBCh3[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if " ascii
    $s2  = "\"getUTCMilliseconds\"]()[\"toString\"](10) == \"20\") {var methWp4 = methJZz8[\"sp\"+\"lit\"](\"``\"); return methWp4[\"reverse" ascii
    $s3  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methPx0(\";``)``'``/``%``P``M``E``T``%``'``(``]``'``s``g``n``i``r``" ascii
    $s4  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methPx0(\";``)``'``/``%``P``M``E``T``%``'``(``]``'``s``g``n``i``r``" ascii
    $s5  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methPx0(\"}``;``h``t``a``P``t``r``o``h``S``.``6``b``W``h``t``e``m``" ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methPx0(\"/``*``@`` ``}``;``)``(``e``s``o``l``c``.``4``o``L``Y``h``" ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methPx0(\"/``*``@`` ``}``;``8``z``Z``J``h``t``e``m`` ``n``r``u``t``" ascii
    $s8  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methPx0(\";``)``\\x22``l``k``w``x``q``n``p``w``q``/``x``m``.``m``o`" ascii
    $s9  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methPx0(\";``)``\\x22``l``l``e``h``S``.``t``p``i``r``c``S``W``\\x22" ascii
    $s10 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methPx0(\";``1``+``1``=``3``e``Z``J``h``t``e``m`` ``r``a``v``;``)``" ascii
    $s11 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methPx0(\";``)``\\x22``x``r``m``h``w``i``j``q``/``m``o``c``.``y``l`" ascii
    $s12 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methPx0(\";``)``\\x22``q``x``n``n``3``g``6``a``b``r``/``t``e``n``.`" ascii
    $s13 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methPx0(\";``9``y``M``O``h``t``e``m`` ``+`` ``3``n``O``h``t``e``m``" ascii
    $s14 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methPx0(\";``)``\\x22``n``u``5``d``f``a``r``/``m``o``c``.``n``v``v`" ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methPx0(\"/``*``@`` ``}``;``4``p``W``h``t``e``m`` ``n``r``u``t``e``" ascii
    $s16 = "function methPx0(methJZz8) {eval(\"/*@cc_on var methBCh3 = new Date() @*/\");methBCh3[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if " ascii
    $s17 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methPx0(\";``)``\\x22``P``T``T``H``L``M``X``.``2``L``M``X``S``M``" ascii
    $s18 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methPx0(\"/``*``@`` ``}``;``4``p``W``h``t``e``m`` ``n``r``u``t``e``" ascii
    $s19 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methPx0(\";``)``\\x22``P``T``T``H``L``M``X``.``2``L``M``X``S``M``" ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methPx0(\"/``*``@`` ``}``;``)``2``z``K``h``t``e``m``(``7``a``U``P``" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}