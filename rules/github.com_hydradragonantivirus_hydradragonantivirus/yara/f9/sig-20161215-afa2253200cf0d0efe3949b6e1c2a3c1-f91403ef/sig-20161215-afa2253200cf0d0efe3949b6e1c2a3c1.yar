rule sig_20161215_afa2253200cf0d0efe3949b6e1c2a3c1 {
  meta:
    description = "datamaliciousorder - file 20161215_afa2253200cf0d0efe3949b6e1c2a3c1.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "68b960809434b09efeec780cf5d614f5ce89081b5f6d2ec3ff301af738211dc3"

  strings:
    $s1  = "function cheburgenVWk0(cheburgenCDe8) {eval(\"/*@cc_on var cheburgenWSz6 = new Date() @*/\");cheburgenWSz6[\"setUTC\"+\"Seconds" ascii
    $s2  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenVWk0(\";``)``\\x22``p``m``h``k``t``e``z``0``/``o``f``n``i``.``" ascii
    $s3  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenVWk0(\";``)``\\x22``p``m``h``k``t``e``z``0``/``o``f``n``i``.``" ascii
    $s4  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenVWk0(\"}``;``h``t``a``P``t``r``o``h``S``.``8``o``W``n``e``g``r" ascii
    $s5  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenVWk0(\";``1``+``1``=``0``v``Z``n``e``g``r``u``b``e``h``c`` ``r" ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenVWk0(\";``3``l``A``O``n``e``g``r``u``b``e``h``c`` ``+`` ``6``d" ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenVWk0(\";``\\x22``/``\\x22``+``\\x22``/``\\x22``+``\\x22``:``" ascii
    $s8  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenVWk0(\";``)``\\x22``g``k``q``0``4``n``w``3``/``u``r``.``o``n``" ascii
    $s9  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenVWk0(\"/``*``@`` ``}``;``}``;``e``u``n``i``t``n``o``c``{`` ``)" ascii
    $s10 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenVWk0(\";``\\x22``k``\\x22`` ``+`` ``\\x22``z``.``\\x22`` ``+``" ascii
    $s11 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenVWk0(\"/``*``@`` ``}``;``8``e``D``C``n``e``g``r``u``b``e``h``c" ascii
    $s12 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenVWk0(\";``)``\\x22``l``l``e``h``S``.``t``p``i``r``c``S``W``\\x" ascii
    $s13 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenVWk0(\";``)``\\x22``\\x22`` ``+`` ``1``h``D``n``e``g``r``u``b`" ascii
    $s14 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenVWk0(\";``)``\\x22``P``T``T``H``L``M``X``.``2``L``M``X``S``M``" ascii
    $s15 = "function cheburgenVWk0(cheburgenCDe8) {eval(\"/*@cc_on var cheburgenWSz6 = new Date() @*/\");cheburgenWSz6[\"setUTC\"+\"Seconds" ascii
    $s16 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenVWk0(\";``)``\\x22``g``k``q``0``4``n``w``3``/``u``r``.``o``n``" ascii
    $s17 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenVWk0(\";``3``l``A``O``n``e``g``r``u``b``e``h``c`` ``+`` ``6``d" ascii
    $s18 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenVWk0(\"\")), 1);//////////////////////////////////////////////" ascii
    $s19 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenVWk0(\";``)``'``/``%``P``M``E``T``%``'``(``]``'``s``g``n``i``r" ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenVWk0(\";``\\x22``X``J``j``u``b``1``g``I``x``1``y``m``N``O``l``" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}