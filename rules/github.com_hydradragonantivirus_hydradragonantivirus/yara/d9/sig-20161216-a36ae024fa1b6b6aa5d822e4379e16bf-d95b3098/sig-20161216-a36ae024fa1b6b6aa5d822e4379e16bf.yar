rule sig_20161216_a36ae024fa1b6b6aa5d822e4379e16bf {
  meta:
    description = "datamaliciousorder - file 20161216_a36ae024fa1b6b6aa5d822e4379e16bf.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "43f8df6dfd0fe9ea958aaa4d9972bbffaf81f8ea1b68138f3f67aa91e297b362"

  strings:
    $s1  = "function methNt3(methJf3) {eval(\"/*@cc_on var methXn7 = new Date() @*/\");methXn7[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (me" ascii
    $s2  = "function methNt3(methJf3) {eval(\"/*@cc_on var methXn7 = new Date() @*/\");methXn7[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (me" ascii
    $s3  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methNt3(\"\"))), 1);///////////////////////////////////////////////" ascii
    $s4  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methNt3(\";``)``\\x22``4``m``e``j``f``/``a``b``.``m``o``c``.``n``o`" ascii
    $s5  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methNt3(\"/``*``@`` ``}``;``}``;``e``u``n``i``t``n``o``c``{`` ``)``" ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methNt3(\"/``*``@`` ``}``;``)``9``k``Y``h``t``e``m``(``1``y``X``A``" ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methNt3(\";``)``\\x22``P``T``T``H``L``M``X``.``2``L``M``X``S``M``" ascii
    $s8  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methNt3(\"/``*``@`` ``}``;``}``;``e``u``n``i``t``n``o``c``{`` ``)``" ascii
    $s9  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methNt3(\";``)``\\x22``4``m``e``j``f``/``a``b``.``m``o``c``.``n``o`" ascii
    $s10 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methNt3(\";``)``\\x22``h``3``e``i``s``m``b``6``5``g``/``m``o``c``.`" ascii
    $s11 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methNt3(\";``\\x22``/``\\x22``+``\\x22``/``\\x22``+``\\x22``:``\\x2" ascii
    $s12 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methNt3(\";``1``+``1``=``8``h``M``h``t``e``m`` ``r``a``v``;``)``\\x" ascii
    $s13 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methNt3(\";``)``\\x22``y``c``h``j``v``f``/``m``o``c``.``y``t``r``e`" ascii
    $s14 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methNt3(\"/``*``@`` ``}``;``1``f``F``h``t``e``m`` ``n``r``u``t``e``" ascii
    $s15 = "UTCMilliseconds\"]()[\"toString\"](10) == \"20\") {var methFf1 = methJf3[\"sp\"+\"lit\"](\"``\"); return methFf1[\"reverse\"]()[" ascii
    $s16 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methNt3(\"/``*``@`` ``}``;``3``f``J``h``t``e``m`` ``n``r``u``t``e``" ascii
    $s17 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methNt3(\";``\\x22``P``S``Y``a``a``L``P``Q``x``t``n``x``F``A``g``M`" ascii
    $s18 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methNt3(\";``\\x22``P``S``Y``a``a``L``P``Q``x``t``n``x``F``A``g``M`" ascii
    $s19 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methNt3(\";``)``'``/``%``P``M``E``T``%``'``(``]``'``s``g``n``i``r``" ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methNt3(\"}``;``h``t``a``P``t``r``o``h``S``.``7``w``I``h``t``e``m``" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}