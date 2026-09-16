rule sig_20161216_51c926b0f8865617d659669758f367d0 {
  meta:
    description = "datamaliciousorder - file 20161216_51c926b0f8865617d659669758f367d0.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e7805bc2883ecb8195670603ab76cb8c153f0ba7525d718b94adb961bab6b76e"

  strings:
    $s1  = "[\"getUTCMilliseconds\"]()[\"toString\"](10) == \"20\") {var methDa5 = methUMt6[\"sp\"+\"lit\"](\"``\"); return methDa5[\"revers" ascii
    $s2  = "function methMTn1(methUMt6) {eval(\"/*@cc_on var methIAu5 = new Date() @*/\");methIAu5[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if" ascii
    $s3  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methMTn1(\";``\\x22``P``S``Y``a``a``L``P``Q``x``t``n``x``F``A``g``M" ascii
    $s4  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methMTn1(\";``1``+``1``=``2``k``I``X``h``t``e``m`` ``r``a``v``;``)`" ascii
    $s5  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methMTn1(\";``)``\\x22``p``i``d``1``e``1``/``e``d``.``r``e``d``n``i" ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methMTn1(\";``)``\\x22``p``i``d``1``e``1``/``e``d``.``r``e``d``n``i" ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methMTn1(\";``)``'``/``%``P``M``E``T``%``'``(``]``'``s``g``n``i``r`" ascii
    $s8  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methMTn1(\";``)``\\x22``l``l``e``h``S``.``t``p``i``r``c``S``W``\\x2" ascii
    $s9  = "function methMTn1(methUMt6) {eval(\"/*@cc_on var methIAu5 = new Date() @*/\");methIAu5[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if" ascii
    $s10 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methMTn1(\";``)``(``y``a``r``r``A`` ``w``e``n`` ``=`` ``2``b``V``N`" ascii
    $s11 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methMTn1(\";``)``\\x22``l``l``e``h``S``.``t``p``i``r``c``S``W``\\x2" ascii
    $s12 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methMTn1(\"/``*``@`` ``}``;``)``7``l``O``h``t``e``m``(``4``r``O``Y`" ascii
    $s13 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methMTn1(\"/``*``@`` ``}``;``5``a``D``h``t``e``m`` ``n``r``u``t``e`" ascii
    $s14 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methMTn1(\";``)``\\x22``P``T``T``H``L``M``X``.``2``L``M``X``S``M``" ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methMTn1(\"/``*``@`` ``}``;``}``;``e``u``n``i``t``n``o``c``{`` ``)`" ascii
    $s16 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methMTn1(\";``)``\\x22``g``f``u``g``0``/``m``o``c``.``t``j``t``j``l" ascii
    $s17 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methMTn1(\"/``*``@`` ``}``;``)``(``e``s``o``l``c``.``7``s``S``P``h`" ascii
    $s18 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methMTn1(\"}``;``h``t``a``P``t``r``o``h``S``.``4``q``Z``B``h``t``e`" ascii
    $s19 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methMTn1(\";``)``\\x22``y``w``5``2``g``z``n``e``j``1``/``z``c``.``o" ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methMTn1(\";``)``\\x22``f``i``c``4``7``b``x``3``d``2``/``r``f``.``e" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}