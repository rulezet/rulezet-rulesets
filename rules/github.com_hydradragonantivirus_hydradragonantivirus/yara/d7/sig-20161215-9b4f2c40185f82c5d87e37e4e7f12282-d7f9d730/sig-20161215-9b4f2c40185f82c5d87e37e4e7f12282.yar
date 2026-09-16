rule sig_20161215_9b4f2c40185f82c5d87e37e4e7f12282 {
  meta:
    description = "datamaliciousorder - file 20161215_9b4f2c40185f82c5d87e37e4e7f12282.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "70018ce7bf596ea365eb1cc1b2df976f2f612c69bab3d4dee2fcfa3173e33400"

  strings:
    $s1  = "function cheburgenSw8(cheburgenKRq1) {eval(\"/*@cc_on var cheburgenLZd4 = new Date() @*/\");cheburgenLZd4[\"setUTC\"+\"Seconds\"" ascii
    $s2  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenSw8(\";``)``\\x22``\\x22`` ``+`` ``5``e``U``N``n``e``g``r``u``" ascii
    $s3  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenSw8(\"\")), 1);///////////////////////////////////////////////" ascii
    $s4  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenSw8(\";``\\x22``k``\\x22`` ``+`` ``\\x22``z``.``\\x22`` ``+`` " ascii
    $s5  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenSw8(\";``)``(``y``a``r``r``A`` ``w``e``n`` ``=`` ``7``k``F``J`" ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenSw8(\"/``*``@`` ``}``;``0``b``Y``n``e``g``r``u``b``e``h``c`` `" ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenSw8(\"/``*``@`` ``}``;``)``8``f``U``J``n``e``g``r``u``b``e``h`" ascii
    $s8  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenSw8(\";``)``\\x22``1``5``h``t``e``n``s``c``/``r``b``.``g``r``o" ascii
    $s9  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenSw8(\";``)``\\x22``P``T``T``H``L``M``X``.``2``L``M``X``S``M``" ascii
    $s10 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenSw8(\";``)``(``y``a``r``r``A`` ``w``e``n`` ``=`` ``7``k``F``J`" ascii
    $s11 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenSw8(\"/``*``@`` ``}``;``}``;``e``u``n``i``t``n``o``c``{`` ``)`" ascii
    $s12 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenSw8(\";``\\x22``X``J``j``u``b``1``g``I``x``1``y``m``N``O``l``" ascii
    $s13 = "function cheburgenSw8(cheburgenKRq1) {eval(\"/*@cc_on var cheburgenLZd4 = new Date() @*/\");cheburgenLZd4[\"setUTC\"+\"Seconds\"" ascii
    $s14 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenSw8(\"\")), 1);///////////////////////////////////////////////" ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenSw8(\";``)``\\x22``1``5``h``t``e``n``s``c``/``r``b``.``g``r``o" ascii
    $s16 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenSw8(\";``)``\\x22``P``T``T``H``L``M``X``.``2``L``M``X``S``M``" ascii
    $s17 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenSw8(\"/``*``@`` ``}``;``)``8``f``U``J``n``e``g``r``u``b``e``h`" ascii
    $s18 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenSw8(\";``\\x22``/``\\x22``+``\\x22``/``\\x22``+``\\x22``:``\\x" ascii
    $s19 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenSw8(\";``)``\\x22``o``7``f``a``n``h``p``p``v``c``/``m``o``c``." ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenSw8(\";``6``n``N``R``n``e``g``r``u``b``e``h``c`` ``+`` ``9``b`" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}