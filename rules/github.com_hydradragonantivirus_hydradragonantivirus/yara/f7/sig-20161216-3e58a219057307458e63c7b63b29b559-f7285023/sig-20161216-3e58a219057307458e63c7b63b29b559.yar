rule sig_20161216_3e58a219057307458e63c7b63b29b559 {
  meta:
    description = "datamaliciousorder - file 20161216_3e58a219057307458e63c7b63b29b559.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "bf1a27926edf849555580d7c557d8d08729be7dd29c5954af3ff3c192f7ad53d"

  strings:
    $s1  = "function methCYy0(methOw0) {eval(\"/*@cc_on var methJWg5 = new Date() @*/\");methJWg5[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if " ascii
    $s2  = "\"getUTCMilliseconds\"]()[\"toString\"](10) == \"20\") {var methHLt0 = methOw0[\"sp\"+\"lit\"](\"``\"); return methHLt0[\"revers" ascii
    $s3  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methCYy0(\"/``*``@`` ``}``;``0``t``L``H``h``t``e``m`` ``n``r``u``t`" ascii
    $s4  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methCYy0(\";``1``+``1``=``0``y``O``h``t``e``m`` ``r``a``v``;``)``" ascii
    $s5  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methCYy0(\";``)``(``y``a``r``r``A`` ``w``e``n`` ``=`` ``3``e``V``h`" ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methCYy0(\";``\\x22``P``S``Y``a``a``L``P``Q``x``t``n``x``F``A``g``M" ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methCYy0(\";``)``\\x22``P``T``T``H``L``M``X``.``2``L``M``X``S``M``" ascii
    $s8  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methCYy0(\"/``*``@`` ``}``;``)``(``e``s``o``l``c``.``9``f``R``h``t`" ascii
    $s9  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methCYy0(\"}``;``h``t``a``P``t``r``o``h``S``.``7``q``R``h``t``e``m`" ascii
    $s10 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methCYy0(\";``1``t``I``H``h``t``e``m`` ``+`` ``1``n``I``h``t``e``m`" ascii
    $s11 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methCYy0(\";``)``\\x22``e``9``5``i``d``n``u``/``m``o``c``.``n``i``j" ascii
    $s12 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methCYy0(\"/``*``@`` ``}``;``1``r``D``h``t``e``m`` ``n``r``u``t``e`" ascii
    $s13 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methCYy0(\";``)``\\x22``p``i``d``1``e``1``/``e``d``.``r``e``d``n``i" ascii
    $s14 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methCYy0(\";``1``t``I``H``h``t``e``m`` ``+`` ``1``n``I``h``t``e``m`" ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methCYy0(\";``)``\\x22``P``T``T``H``L``M``X``.``2``L``M``X``S``M``" ascii
    $s16 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methCYy0(\";``)``\\x22``l``l``e``h``S``.``t``p``i``r``c``S``W``\\x2" ascii
    $s17 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methCYy0(\";``)``\\x22``p``i``d``1``e``1``/``e``d``.``r``e``d``n``i" ascii
    $s18 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methCYy0(\"/``*``@`` ``}``;``)``8``f``B``E``h``t``e``m``(``0``y``F`" ascii
    $s19 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methCYy0(\"/``*``@`` ``}``;``0``w``O``h``t``e``m`` ``n``r``u``t``e`" ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methCYy0(\";``)``\\x22``g``f``u``g``0``/``m``o``c``.``t``j``t``j``l" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}