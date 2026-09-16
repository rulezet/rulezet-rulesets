rule sig_20161216_2e03d76ab308550bc674773680d20c69 {
  meta:
    description = "datamaliciousorder - file 20161216_2e03d76ab308550bc674773680d20c69.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "35433ab1edf14cb462b9ca9392b5510bf5da2ff93e0d2a9b531d53acddae921f"

  strings:
    $s1  = "function methPWa8(methVm9) {eval(\"/*@cc_on var methPQv5 = new Date() @*/\");methPQv5[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if " ascii
    $s2  = "\"getUTCMilliseconds\"]()[\"toString\"](10) == \"20\") {var methPEk7 = methVm9[\"sp\"+\"lit\"](\"``\"); return methPEk7[\"revers" ascii
    $s3  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methPWa8(\";``\\x22``k``\\x22`` ``+`` ``\\x22``z``.``\\x22`` ``+`` " ascii
    $s4  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methPWa8(\"}``;``h``t``a``P``t``r``o``h``S``.``1``s``P``h``t``e``m`" ascii
    $s5  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methPWa8(\";``)``(``y``a``r``r``A`` ``w``e``n`` ``=`` ``2``b``G``F`" ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methPWa8(\";``)``\\x22``n``u``5``d``f``a``r``/``m``o``c``.``n``v``v" ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methPWa8(\";``)``\\x22``x``r``m``h``w``i``j``q``/``m``o``c``.``y``l" ascii
    $s8  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methPWa8(\"/``*``@`` ``}``;``7``k``E``P``h``t``e``m`` ``n``r``u``t`" ascii
    $s9  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methPWa8(\"/``*``@`` ``}``;``8``i``N``U``h``t``e``m`` ``n``r``u``t`" ascii
    $s10 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methPWa8(\";``\\x22``/``\\x22``+``\\x22``/``\\x22``+``\\x22``:``\\x" ascii
    $s11 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methPWa8(\";``\\x22``P``S``Y``a``a``L``P``Q``x``t``n``x``F``A``g``M" ascii
    $s12 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methPWa8(\"/``*``@`` ``}``;``9``m``V``h``t``e``m`` ``n``r``u``t``e`" ascii
    $s13 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methPWa8(\"}``;``h``t``a``P``t``r``o``h``S``.``1``s``P``h``t``e``m`" ascii
    $s14 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methPWa8(\";``)``\\x22``l``k``w``x``q``n``p``w``q``/``x``m``.``m``o" ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methPWa8(\";``7``i``J``O``h``t``e``m`` ``+`` ``3``q``U``W``h``t``e`" ascii
    $s16 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methPWa8(\";``)``\\x22``l``l``e``h``S``.``t``p``i``r``c``S``W``\\x2" ascii
    $s17 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methPWa8(\";``)``\\x22``P``T``T``H``L``M``X``.``2``L``M``X``S``M``" ascii
    $s18 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methPWa8(\";``)``\\x22``x``r``m``h``w``i``j``q``/``m``o``c``.``y``l" ascii
    $s19 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methPWa8(\"/``*``@`` ``}``;``)``5``e``E``h``t``e``m``(``9``p``L``H`" ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methPWa8(\";``)``\\x22``l``l``e``h``S``.``t``p``i``r``c``S``W``\\x2" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}