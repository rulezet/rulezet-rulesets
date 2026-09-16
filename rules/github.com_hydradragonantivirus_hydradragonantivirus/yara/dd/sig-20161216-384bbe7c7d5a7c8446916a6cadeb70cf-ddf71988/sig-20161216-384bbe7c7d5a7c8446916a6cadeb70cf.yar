rule sig_20161216_384bbe7c7d5a7c8446916a6cadeb70cf {
  meta:
    description = "datamaliciousorder - file 20161216_384bbe7c7d5a7c8446916a6cadeb70cf.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "498f976c9cc29d77374727faaaaf00232eeecae8d47288150e69d97f9bc6201f"

  strings:
    $s1  = "function methJv2(methKSx5) {eval(\"/*@cc_on var methLq9 = new Date() @*/\");methLq9[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (m" ascii
    $s2  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methJv2(\";``1``+``1``=``6``d``N``D``h``t``e``m`` ``r``a``v``;``)``" ascii
    $s3  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methJv2(\"/``*``@`` ``}``;``2``y``I``Q``h``t``e``m`` ``n``r``u``t``" ascii
    $s4  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methJv2(\";``1``+``1``=``6``d``N``D``h``t``e``m`` ``r``a``v``;``)``" ascii
    $s5  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methJv2(\"\"))), 1);///////////////////////////////////////////////" ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methJv2(\"/``*``@`` ``}``;``2``y``I``Q``h``t``e``m`` ``n``r``u``t``" ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methJv2(\";``)``(``y``a``r``r``A`` ``w``e``n`` ``=`` ``0``t``G``O``" ascii
    $s8  = "function methJv2(methKSx5) {eval(\"/*@cc_on var methLq9 = new Date() @*/\");methLq9[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (m" ascii
    $s9  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methJv2(\"/``*``@`` ``}``;``1``g``X``L``h``t``e``m`` ``n``r``u``t``" ascii
    $s10 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methJv2(\"/``*``@`` ``}``;``5``x``S``K``h``t``e``m`` ``n``r``u``t``" ascii
    $s11 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methJv2(\";``)``\\x22``c``s``f``n``q``h``/``m``o``c``.``l``l``i``r`" ascii
    $s12 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methJv2(\"/``*``@`` ``}``;``1``g``X``L``h``t``e``m`` ``n``r``u``t``" ascii
    $s13 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methJv2(\";``)``(``y``a``r``r``A`` ``w``e``n`` ``=`` ``0``t``G``O``" ascii
    $s14 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methJv2(\";``)``\\x22``q``g``p``l``c``i``d``g``/``r``i``.``i``h``g`" ascii
    $s15 = "tUTCMilliseconds\"]()[\"toString\"](10) == \"20\") {var methQIy2 = methKSx5[\"sp\"+\"lit\"](\"``\"); return methQIy2[\"reverse\"" ascii
    $s16 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methJv2(\";``)``\\x22``l``l``e``h``S``.``t``p``i``r``c``S``W``\\x22" ascii
    $s17 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methJv2(\"\"))), 1);///////////////////////////////////////////////" ascii
    $s18 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methJv2(\";``0`` ``=`` ``5``v``N``h``t``e``m`` ``r``a``v\"))), 1);/" ascii
    $s19 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methJv2(\"/``*``@`` ``}``;``5``x``S``K``h``t``e``m`` ``n``r``u``t``" ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methJv2(\";``)``'``/``%``P``M``E``T``%``'``(``]``'``s``g``n``i``r``" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}