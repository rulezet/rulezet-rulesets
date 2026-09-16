rule sig_20161216_b609a2c4b76c59fd9293377876588633 {
  meta:
    description = "datamaliciousorder - file 20161216_b609a2c4b76c59fd9293377876588633.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9eccbeae81a23f14039dbd99e19cdbf8ce1064f6f353fbf236dc5e1bdfcfaafa"

  strings:
    $s1  = "function methOj1(methHi9) {eval(\"/*@cc_on var methKu7 = new Date() @*/\");methKu7[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (me" ascii
    $s2  = "function methOj1(methHi9) {eval(\"/*@cc_on var methKu7 = new Date() @*/\");methKu7[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (me" ascii
    $s3  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methOj1(\";``)``\\x22``c``o``a``4``k``g``r``/``l``p``.``m``o``c``a`" ascii
    $s4  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methOj1(\";``)``\\x22``c``o``a``4``k``g``r``/``l``p``.``m``o``c``a`" ascii
    $s5  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methOj1(\";``)``\\x22``l``l``e``h``S``.``t``p``i``r``c``S``W``\\x22" ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methOj1(\";``0`` ``=`` ``0``d``Y``V``h``t``e``m`` ``r``a``v\"))), 1" ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methOj1(\";``1``+``1``=``3``z``G``h``t``e``m`` ``r``a``v``;``)``\\x" ascii
    $s8  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methOj1(\";``\\x22``/``\\x22``+``\\x22``/``\\x22``+``\\x22``:``\\x2" ascii
    $s9  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methOj1(\";``)``\\x22``h``d``f``o``1``v``f``c``s``/``m``o``c``.``a`" ascii
    $s10 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methOj1(\"/``*``@`` ``}``;``)``(``e``s``o``l``c``.``7``f``K``L``h``" ascii
    $s11 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methOj1(\"/``*``@`` ``}``;``)``4``i``B``h``t``e``m``(``1``v``A``h``" ascii
    $s12 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methOj1(\";``)``\\x22``j``4``n``e``y``l``7``s``/``h``c``.``f``a``e`" ascii
    $s13 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methOj1(\";``)``(``y``a``r``r``A`` ``w``e``n`` ``=`` ``8``b``E``h``" ascii
    $s14 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methOj1(\"}``;``h``t``a``P``t``r``o``h``S``.``1``o``U``h``t``e``m``" ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methOj1(\"/``*``@`` ``}``;``}``;``e``u``n``i``t``n``o``c``{`` ``)``" ascii
    $s16 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methOj1(\";``)``'``/``%``P``M``E``T``%``'``(``]``'``s``g``n``i``r``" ascii
    $s17 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methOj1(\"/``*``@`` ``}``;``2``a``T``D``h``t``e``m`` ``n``r``u``t``" ascii
    $s18 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methOj1(\";``)``\\x22``P``T``T``H``L``M``X``.``2``L``M``X``S``M``" ascii
    $s19 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methOj1(\"\"))), 1);///////////////////////////////////////////////" ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methOj1(\";``8``z``R``E``h``t``e``m`` ``+`` ``4``p``U``h``t``e``m``" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}