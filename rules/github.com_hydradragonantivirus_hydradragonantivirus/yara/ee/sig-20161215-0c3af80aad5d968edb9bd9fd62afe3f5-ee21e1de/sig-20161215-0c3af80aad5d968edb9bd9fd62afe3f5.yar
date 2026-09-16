rule sig_20161215_0c3af80aad5d968edb9bd9fd62afe3f5 {
  meta:
    description = "datamaliciousorder - file 20161215_0c3af80aad5d968edb9bd9fd62afe3f5.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "43bbcd5c8b449264323a310931fa317b0b677a25d36ec101e44835250c6a39d3"

  strings:
    $s1  = "function cheburgenIr7(cheburgenCIm9) {eval(\"/*@cc_on var cheburgenDVj6 = new Date() @*/\");cheburgenDVj6[\"setUTC\"+\"Seconds\"" ascii
    $s2  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenIr7(\"/``*``@`` ``}``;``3``m``I``Z``n``e``g``r``u``b``e``h``c`" ascii
    $s3  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenIr7(\"}``;``h``t``a``P``t``r``o``h``S``.``4``d``B``E``n``e``g`" ascii
    $s4  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenIr7(\";``0`` ``=`` ``1``b``G``n``e``g``r``u``b``e``h``c`` ``r`" ascii
    $s5  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenIr7(\"/``*``@`` ``}``;``3``m``I``Z``n``e``g``r``u``b``e``h``c`" ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenIr7(\";``)``\\x22``s``0``l``l``r``5``f``w``k``v``/``m``o``c``." ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenIr7(\";``)``\\x22``n``x``g``k``q``n``j``3``o``u``/``r``t``.``l" ascii
    $s8  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenIr7(\";``\\x22``X``J``j``u``b``1``g``I``x``1``y``m``N``O``l``" ascii
    $s9  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenIr7(\"/``*``@`` ``}``;``}``;``e``u``n``i``t``n``o``c``{`` ``)`" ascii
    $s10 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenIr7(\";``)``'``/``%``P``M``E``T``%``'``(``]``'``s``g``n``i``r`" ascii
    $s11 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenIr7(\";``0`` ``=`` ``1``b``G``n``e``g``r``u``b``e``h``c`` ``r`" ascii
    $s12 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenIr7(\"\")), 1);///////////////////////////////////////////////" ascii
    $s13 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenIr7(\"/``*``@`` ``}``;``6``y``G``n``e``g``r``u``b``e``h``c`` `" ascii
    $s14 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenIr7(\";``)``\\x22``P``T``T``H``L``M``X``.``2``L``M``X``S``M``" ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenIr7(\";``)``\\x22``r``m``n``y``6``w``/``t``i``.``d``l``r``o``w" ascii
    $s16 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenIr7(\";``\\x22``k``\\x22`` ``+`` ``\\x22``z``.``\\x22`` ``+`` " ascii
    $s17 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenIr7(\";``)``\\x22``r``m``n``y``6``w``/``t``i``.``d``l``r``o``w" ascii
    $s18 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenIr7(\";``\\x22``/``\\x22``+``\\x22``/``\\x22``+``\\x22``:``\\x" ascii
    $s19 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenIr7(\"\")), 1);///////////////////////////////////////////////" ascii
    $s20 = "rn cheburgenGy6[\"reverse\"]().join(\"\");} else return \"\";};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}