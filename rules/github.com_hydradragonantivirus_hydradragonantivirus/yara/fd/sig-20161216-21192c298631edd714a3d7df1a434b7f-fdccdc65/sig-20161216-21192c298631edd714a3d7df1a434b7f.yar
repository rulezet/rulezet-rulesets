rule sig_20161216_21192c298631edd714a3d7df1a434b7f {
  meta:
    description = "datamaliciousorder - file 20161216_21192c298631edd714a3d7df1a434b7f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "062103d2249281ad81192a4138299dc5d751f76ac99fa1b0dc77a18f13782d75"

  strings:
    $s1  = "function methCt4(methFKv2) {eval(\"/*@cc_on var methFr9 = new Date() @*/\");methFr9[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (m" ascii
    $s2  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methCt4(\";``\\x22``/``\\x22``+``\\x22``/``\\x22``+``\\x22``:``\\x2" ascii
    $s3  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methCt4(\";``)``\\x22``e``9``5``i``d``n``u``/``m``o``c``.``n``i``j`" ascii
    $s4  = "function methCt4(methFKv2) {eval(\"/*@cc_on var methFr9 = new Date() @*/\");methFr9[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (m" ascii
    $s5  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methCt4(\"/``*``@`` ``}``;``}``;``e``u``n``i``t``n``o``c``{`` ``)``" ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methCt4(\";``2``e``X``Q``h``t``e``m`` ``+`` ``1``v``A``K``h``t``e``" ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methCt4(\";``1``+``1``=``9``m``I``L``h``t``e``m`` ``r``a``v``;``)``" ascii
    $s8  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methCt4(\";``)``\\x22``g``f``u``g``0``/``m``o``c``.``t``j``t``j``l`" ascii
    $s9  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methCt4(\";``)``\\x22``g``f``u``g``0``/``m``o``c``.``t``j``t``j``l`" ascii
    $s10 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methCt4(\";``0`` ``=`` ``5``r``P``M``h``t``e``m`` ``r``a``v\"))), 1" ascii
    $s11 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methCt4(\"/``*``@`` ``}``;``4``r``K``h``t``e``m`` ``n``r``u``t``e``" ascii
    $s12 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methCt4(\"/``*``@`` ``}``;``8``z``X``h``t``e``m`` ``n``r``u``t``e``" ascii
    $s13 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methCt4(\";``)``'``/``%``P``M``E``T``%``'``(``]``'``s``g``n``i``r``" ascii
    $s14 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methCt4(\";``)``\\x22``l``l``e``h``S``.``t``p``i``r``c``S``W``\\x22" ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methCt4(\";``\\x22``P``S``Y``a``a``L``P``Q``x``t``n``x``F``A``g``M`" ascii
    $s16 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methCt4(\";``)``\\x22``d``v``c``t``f``/``z``c``.``y``n``i``t``e``l`" ascii
    $s17 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methCt4(\";``)``\\x22``e``9``5``i``d``n``u``/``m``o``c``.``n``i``j`" ascii
    $s18 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methCt4(\"\"))), 1);///////////////////////////////////////////////" ascii
    $s19 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methCt4(\";``\\x22``k``\\x22`` ``+`` ``\\x22``z``.``\\x22`` ``+`` `" ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methCt4(\";``)``\\x22``P``T``T``H``L``M``X``.``2``L``M``X``S``M``" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}