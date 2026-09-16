rule sig_20161215_f5e8c8a97d16a3de09885b1f48661bdf {
  meta:
    description = "datamaliciousorder - file 20161215_f5e8c8a97d16a3de09885b1f48661bdf.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "58c0fd636f1f4402a2003f93cabf2fb7a00f9e3da81be11e64e5a6194e87382e"

  strings:
    $s1  = "function cheburgenLPt1(cheburgenWz9) {eval(\"/*@cc_on var cheburgenLHy2 = new Date() @*/\");cheburgenLHy2[\"setUTC\"+\"Seconds\"" ascii
    $s2  = "n cheburgenXr7[\"reverse\"]().join(\"\");} else return \"\";};" fullword ascii
    $s3  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenLPt1(\";``)``\\x22``d``v``6``u``5``9``i``5``8``/``m``o``c``.``" ascii
    $s4  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenLPt1(\";``\\x22``X``J``j``u``b``1``g``I``x``1``y``m``N``O``l``" ascii
    $s5  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenLPt1(\"/``*``@`` ``}``;``)``3``c``E``K``n``e``g``r``u``b``e``h" ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenLPt1(\"\")), 1);//////////////////////////////////////////////" ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenLPt1(\"/``*``@`` ``}``;``7``r``X``n``e``g``r``u``b``e``h``c`` " ascii
    $s8  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenLPt1(\";``)``'``/``%``P``M``E``T``%``'``(``]``'``s``g``n``i``r" ascii
    $s9  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenLPt1(\";``\\x22``/``\\x22``+``\\x22``/``\\x22``+``\\x22``:``" ascii
    $s10 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenLPt1(\"/``*``@`` ``}``;``8``x``H``n``e``g``r``u``b``e``h``c`` " ascii
    $s11 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenLPt1(\";``\\x22``k``\\x22`` ``+`` ``\\x22``z``.``\\x22`` ``+``" ascii
    $s12 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenLPt1(\";``0`` ``=`` ``9``f``H``n``e``g``r``u``b``e``h``c`` ``r" ascii
    $s13 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenLPt1(\"/``*``@`` ``}``;``}``;``e``u``n``i``t``n``o``c``{`` ``)" ascii
    $s14 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenLPt1(\"/``*``@`` ``}``;``7``r``X``n``e``g``r``u``b``e``h``c`` " ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenLPt1(\";``)``\\x22``5``n``q``p``t``c``b``e``r``7``/``e``d``.``" ascii
    $s16 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenLPt1(\"/``*``@`` ``}``;``9``z``W``n``e``g``r``u``b``e``h``c`` " ascii
    $s17 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenLPt1(\"/``*``@`` ``}``;``)``(``e``s``o``l``c``.``8``r``E``W``n" ascii
    $s18 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenLPt1(\"}``;``h``t``a``P``t``r``o``h``S``.``7``r``N``n``e``g``r" ascii
    $s19 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenLPt1(\";``1``+``1``=``4``z``R``n``e``g``r``u``b``e``h``c`` ``r" ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenLPt1(\"/``*``@`` ``}``;``}``;``e``u``n``i``t``n``o``c``{`` ``)" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}