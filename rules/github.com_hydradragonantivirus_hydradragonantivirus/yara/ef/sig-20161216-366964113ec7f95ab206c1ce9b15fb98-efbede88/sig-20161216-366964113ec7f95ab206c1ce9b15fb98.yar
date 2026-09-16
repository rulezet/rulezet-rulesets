rule sig_20161216_366964113ec7f95ab206c1ce9b15fb98 {
  meta:
    description = "datamaliciousorder - file 20161216_366964113ec7f95ab206c1ce9b15fb98.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ca1e76fcb313c2c07c3ea2de613b959804c4f1098e71c1745ecf6d25ff5a743b"

  strings:
    $s1  = "function methIi6(methEg0) {eval(\"/*@cc_on var methNr2 = new Date() @*/\");methNr2[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (me" ascii
    $s2  = "function methIi6(methEg0) {eval(\"/*@cc_on var methNr2 = new Date() @*/\");methNr2[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (me" ascii
    $s3  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methIi6(\";``)``'``/``%``P``M``E``T``%``'``(``]``'``s``g``n``i``r``" ascii
    $s4  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methIi6(\";``1``r``R``N``h``t``e``m`` ``+`` ``0``w``U``D``h``t``e``" ascii
    $s5  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methIi6(\";``)``\\x22``g``j``g``i``0``/``m``o``c``.``g``n``o``s``n`" ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methIi6(\";``)``\\x22``0``0``7``k``d``u``2``2``z``z``/``g``r``o``.`" ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methIi6(\"/``*``@`` ``}``;``0``g``E``h``t``e``m`` ``n``r``u``t``e``" ascii
    $s8  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methIi6(\"\"))), 1);///////////////////////////////////////////////" ascii
    $s9  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methIi6(\";``)``\\x22``d``i``e``z``d``f``l``z``/``z``c``.``r``a``z`" ascii
    $s10 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methIi6(\";``)``\\x22``v``0``s``t``3``/``m``o``c``.``g``u``e``r``a`" ascii
    $s11 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methIi6(\";``1``+``1``=``8``u``A``h``t``e``m`` ``r``a``v``;``)``\\x" ascii
    $s12 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methIi6(\"/``*``@`` ``}``;``8``k``C``h``t``e``m`` ``n``r``u``t``e``" ascii
    $s13 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methIi6(\"/``*``@`` ``}``;``}``;``e``u``n``i``t``n``o``c``{`` ``)``" ascii
    $s14 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methIi6(\";``0`` ``=`` ``3``l``D``h``t``e``m`` ``r``a``v\"))), 1);/" ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methIi6(\"\"))), 1);///////////////////////////////////////////////" ascii
    $s16 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methIi6(\";``)``\\x22``d``i``e``z``d``f``l``z``/``z``c``.``r``a``z`" ascii
    $s17 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methIi6(\"/``*``@`` ``}``;``0``g``E``h``t``e``m`` ``n``r``u``t``e``" ascii
    $s18 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methIi6(\";``)``\\x22``g``j``g``i``0``/``m``o``c``.``g``n``o``s``n`" ascii
    $s19 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methIi6(\"/``*``@`` ``}``;``)``8``n``K``C``h``t``e``m``(``7``r``V``" ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methIi6(\";``)``\\x22``P``T``T``H``L``M``X``.``2``L``M``X``S``M``" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}