rule sig_20161216_74006126fe372a94767a677359a06959 {
  meta:
    description = "datamaliciousorder - file 20161216_74006126fe372a94767a677359a06959.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a01a0136192bbb6f56901540dd141f3143f4b9278985062722dd0cfb3f6ffac1"

  strings:
    $s1  = "function methVRb9(methRe2) {eval(\"/*@cc_on var methSt2 = new Date() @*/\");methSt2[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (m" ascii
    $s2  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methVRb9(\";``)``(``y``a``r``r``A`` ``w``e``n`` ``=`` ``2``x``V``X`" ascii
    $s3  = "tUTCMilliseconds\"]()[\"toString\"](10) == \"20\") {var methTw7 = methRe2[\"sp\"+\"lit\"](\"``\"); return methTw7[\"reverse\"]()" ascii
    $s4  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methVRb9(\"/``*``@`` ``}``;``)``(``e``s``o``l``c``.``6``e``S``D``h`" ascii
    $s5  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methVRb9(\";``)``'``/``%``P``M``E``T``%``'``(``]``'``s``g``n``i``r`" ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methVRb9(\"/``*``@`` ``}``;``7``w``T``h``t``e``m`` ``n``r``u``t``e`" ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methVRb9(\";``7``f``W``Y``h``t``e``m`` ``+`` ``5``x``P``h``t``e``m`" ascii
    $s8  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methVRb9(\"/``*``@`` ``}``;``2``e``R``h``t``e``m`` ``n``r``u``t``e`" ascii
    $s9  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methVRb9(\"}``;``h``t``a``P``t``r``o``h``S``.``6``m``I``Z``h``t``e`" ascii
    $s10 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methVRb9(\"/``*``@`` ``}``;``2``e``R``h``t``e``m`` ``n``r``u``t``e`" ascii
    $s11 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methVRb9(\";``\\x22``P``S``Y``a``a``L``P``Q``x``t``n``x``F``A``g``M" ascii
    $s12 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methVRb9(\";``0`` ``=`` ``5``c``O``h``t``e``m`` ``r``a``v\"))), 1);" ascii
    $s13 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methVRb9(\";``)``\\x22``s``c``y``g``8``s``l``g``y``/``s``u``.``e``m" ascii
    $s14 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methVRb9(\"/``*``@`` ``}``;``)``8``c``J``h``t``e``m``(``4``u``G``h`" ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methVRb9(\";``7``f``W``Y``h``t``e``m`` ``+`` ``5``x``P``h``t``e``m`" ascii
    $s16 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methVRb9(\";``)``\\x22``w``s``x``y``r``f``r``a``o``w``/``m``o``c``." ascii
    $s17 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methVRb9(\"/``*``@`` ``}``;``7``w``T``h``t``e``m`` ``n``r``u``t``e`" ascii
    $s18 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methVRb9(\"/``*``@`` ``}``;``)``(``e``s``o``l``c``.``6``e``S``D``h`" ascii
    $s19 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methVRb9(\";``)``(``y``a``r``r``A`` ``w``e``n`` ``=`` ``2``x``V``X`" ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methVRb9(\"/``*``@`` ``}``;``}``;``e``u``n``i``t``n``o``c``{`` ``)`" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}