rule sig_20161216_e9d928060b6f63e981158c5d4de376c9 {
  meta:
    description = "datamaliciousorder - file 20161216_e9d928060b6f63e981158c5d4de376c9.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "10889fed3ea991095611a8dd98adb1e5d48d31392f3e1db17b4c5a4adb7b3072"

  strings:
    $s1  = "function methCp6(methIj6) {eval(\"/*@cc_on var methGDm4 = new Date() @*/\");methGDm4[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (" ascii
    $s2  = "getUTCMilliseconds\"]()[\"toString\"](10) == \"20\") {var methWAu6 = methIj6[\"sp\"+\"lit\"](\"``\"); return methWAu6[\"reverse" ascii
    $s3  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methCp6(\";``)``\\x22``c``m``c``s``p``5``w``6``c``/``m``o``c``.``n`" ascii
    $s4  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methCp6(\";``1``+``1``=``2``b``D``h``t``e``m`` ``r``a``v``;``)``\\x" ascii
    $s5  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methCp6(\";``\\x22``/``\\x22``+``\\x22``/``\\x22``+``\\x22``:``\\x2" ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methCp6(\";``)``(``y``a``r``r``A`` ``w``e``n`` ``=`` ``0``v``O``h``" ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methCp6(\"/``*``@`` ``}``;``)``3``t``E``h``t``e``m``(``8``h``V``h``" ascii
    $s8  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methCp6(\"}``;``h``t``a``P``t``r``o``h``S``.``7``x``B``Y``h``t``e``" ascii
    $s9  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methCp6(\";``)``\\x22``e``9``5``i``d``n``u``/``m``o``c``.``n``i``j`" ascii
    $s10 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methCp6(\";``\\x22``P``S``Y``a``a``L``P``Q``x``t``n``x``F``A``g``M`" ascii
    $s11 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methCp6(\"/``*``@`` ``}``;``)``3``t``E``h``t``e``m``(``8``h``V``h``" ascii
    $s12 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methCp6(\"/``*``@`` ``}``;``6``j``I``h``t``e``m`` ``n``r``u``t``e``" ascii
    $s13 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methCp6(\";``)``\\x22``P``T``T``H``L``M``X``.``2``L``M``X``S``M``" ascii
    $s14 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methCp6(\";``)``\\x22``c``m``c``s``p``5``w``6``c``/``m``o``c``.``n`" ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methCp6(\"/``*``@`` ``}``;``)``(``e``s``o``l``c``.``9``s``H``h``t``" ascii
    $s16 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methCp6(\";``0`` ``=`` ``1``k``B``h``t``e``m`` ``r``a``v\"))), 1);/" ascii
    $s17 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methCp6(\"\"))), 1);///////////////////////////////////////////////" ascii
    $s18 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methCp6(\"\"))), 1);///////////////////////////////////////////////" ascii
    $s19 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methCp6(\"/``*``@`` ``}``;``6``u``A``W``h``t``e``m`` ``n``r``u``t``" ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methCp6(\";``)``'``/``%``P``M``E``T``%``'``(``]``'``s``g``n``i``r``" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}