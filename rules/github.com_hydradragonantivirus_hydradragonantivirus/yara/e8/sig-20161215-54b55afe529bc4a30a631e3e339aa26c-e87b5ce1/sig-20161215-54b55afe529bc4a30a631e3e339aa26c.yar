rule sig_20161215_54b55afe529bc4a30a631e3e339aa26c {
  meta:
    description = "datamaliciousorder - file 20161215_54b55afe529bc4a30a631e3e339aa26c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6db3c9e848782ff1998e5c897e99387870087588aef9acd9627df8acade29698"

  strings:
    $s1  = "function cheburgenXh0(cheburgenSOq3) {eval(\"/*@cc_on var cheburgenAk2 = new Date() @*/\");cheburgenAk2[\"setUTC\"+\"Seconds\"](" ascii
    $s2  = "20\");if (cheburgenAk2[\"getUTCMilliseconds\"]()[\"toString\"](10) == \"20\") {var cheburgenXWz9 = cheburgenSOq3[\"split\"](\"``" ascii
    $s3  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenXh0(\"\")), 1);///////////////////////////////////////////////" ascii
    $s4  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenXh0(\"/``*``@`` ``}``;``}``;``e``u``n``i``t``n``o``c``{`` ``)`" ascii
    $s5  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenXh0(\"/``*``@`` ``}``;``)``(``e``s``o``l``c``.``5``w``M``n``e`" ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenXh0(\"/``*``@`` ``}``;``1``v``Z``V``n``e``g``r``u``b``e``h``c`" ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenXh0(\";``)``'``/``%``P``M``E``T``%``'``(``]``'``s``g``n``i``r`" ascii
    $s8  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenXh0(\";``)``\\x22``c``w``m``o``8``r``/``a``c``.``e``c``a``r``g" ascii
    $s9  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenXh0(\";``\\x22``/``\\x22``+``\\x22``/``\\x22``+``\\x22``:``\\x" ascii
    $s10 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenXh0(\"}``;``h``t``a``P``t``r``o``h``S``.``5``k``E``n``e``g``r`" ascii
    $s11 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenXh0(\";``)``\\x22``4``j``g``a``q``s``/``m``o``c``.``h``c``e``t" ascii
    $s12 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenXh0(\";``0`` ``=`` ``7``x``Z``Q``n``e``g``r``u``b``e``h``c`` `" ascii
    $s13 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenXh0(\";``\\x22``k``\\x22`` ``+`` ``\\x22``z``.``\\x22`` ``+`` " ascii
    $s14 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenXh0(\"/``*``@`` ``}``;``3``q``O``S``n``e``g``r``u``b``e``h``c`" ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenXh0(\";``0``a``R``n``e``g``r``u``b``e``h``c`` ``+`` ``8``y``M`" ascii
    $s16 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenXh0(\";``)``(``y``a``r``r``A`` ``w``e``n`` ``=`` ``6``x``L``n`" ascii
    $s17 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenXh0(\"/``*``@`` ``}``;``3``q``O``S``n``e``g``r``u``b``e``h``c`" ascii
    $s18 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenXh0(\";``\\x22``X``J``j``u``b``1``g``I``x``1``y``m``N``O``l``" ascii
    $s19 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenXh0(\";``)``\\x22``\\x22`` ``+`` ``0``l``T``n``e``g``r``u``b``" ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenXh0(\";``)``\\x22``7``p``j``7``o``t``/``a``c``.``p``r``o``c``e" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}