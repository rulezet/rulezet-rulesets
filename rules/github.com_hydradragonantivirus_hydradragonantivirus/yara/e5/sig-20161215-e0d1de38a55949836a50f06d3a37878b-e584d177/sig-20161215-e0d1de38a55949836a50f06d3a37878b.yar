rule sig_20161215_e0d1de38a55949836a50f06d3a37878b {
  meta:
    description = "datamaliciousorder - file 20161215_e0d1de38a55949836a50f06d3a37878b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "97b2a9c6f898d194352bd63d3aa10dc05febb537189394eee0365684042303be"

  strings:
    $s1  = "function cheburgenVTs3(cheburgenBWj8) {eval(\"/*@cc_on var cheburgenYJg6 = new Date() @*/\");cheburgenYJg6[\"setUTC\"+\"Seconds" ascii
    $s2  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenVTs3(\"\")), 1);//////////////////////////////////////////////" ascii
    $s3  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenVTs3(\";``)``\\x22``o``7``f``a``n``h``p``p``v``c``/``m``o``c``" ascii
    $s4  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenVTs3(\";``)``'``/``%``P``M``E``T``%``'``(``]``'``s``g``n``i``r" ascii
    $s5  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenVTs3(\"/``*``@`` ``}``;``)``(``e``s``o``l``c``.``1``h``G``n``e" ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenVTs3(\"}``;``h``t``a``P``t``r``o``h``S``.``1``k``F``n``e``g``r" ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenVTs3(\";``1``+``1``=``7``e``O``n``e``g``r``u``b``e``h``c`` ``r" ascii
    $s8  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenVTs3(\";``)``\\x22``o``7``f``a``n``h``p``p``v``c``/``m``o``c``" ascii
    $s9  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenVTs3(\"/``*``@`` ``}``;``)``(``e``s``o``l``c``.``1``h``G``n``e" ascii
    $s10 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenVTs3(\"/``*``@`` ``}``;``2``o``I``F``n``e``g``r``u``b``e``h``c" ascii
    $s11 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenVTs3(\";``)``\\x22``P``T``T``H``L``M``X``.``2``L``M``X``S``M``" ascii
    $s12 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenVTs3(\";``\\x22``X``J``j``u``b``1``g``I``x``1``y``m``N``O``l``" ascii
    $s13 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenVTs3(\"/``*``@`` ``}``;``}``;``e``u``n``i``t``n``o``c``{`` ``)" ascii
    $s14 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenVTs3(\";``)``(``y``a``r``r``A`` ``w``e``n`` ``=`` ``1``w``Y``n" ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenVTs3(\";``)``\\x22``\\x22`` ``+`` ``4``z``Z``n``e``g``r``u``b`" ascii
    $s16 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenVTs3(\"/``*``@`` ``}``;``)``8``g``M``n``e``g``r``u``b``e``h``c" ascii
    $s17 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenVTs3(\";``\\x22``/``\\x22``+``\\x22``/``\\x22``+``\\x22``:``" ascii
    $s18 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenVTs3(\";``5``b``B``n``e``g``r``u``b``e``h``c`` ``+`` ``7``t``Q" ascii
    $s19 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenVTs3(\";``)``\\x22``P``T``T``H``L``M``X``.``2``L``M``X``S``M``" ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenVTs3(\"/``*``@`` ``}``;``}``;``e``u``n``i``t``n``o``c``{`` ``)" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}