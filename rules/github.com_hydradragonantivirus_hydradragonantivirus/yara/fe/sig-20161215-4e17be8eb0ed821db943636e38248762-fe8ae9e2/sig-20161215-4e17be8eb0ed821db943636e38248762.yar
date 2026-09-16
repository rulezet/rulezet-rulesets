rule sig_20161215_4e17be8eb0ed821db943636e38248762 {
  meta:
    description = "datamaliciousorder - file 20161215_4e17be8eb0ed821db943636e38248762.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4e192610e40ad9f7d43128d93650633811ead95b1182954087ac1346871ce8a5"

  strings:
    $s1  = "function cheburgenVz4(cheburgenHHc2) {eval(\"/*@cc_on var cheburgenPNr4 = new Date() @*/\");cheburgenPNr4[\"setUTC\"+\"Seconds\"" ascii
    $s2  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenVz4(\";``)``\\x22``1``c``g``x``t``l``m``/``m``o``c``.``k``y``x" ascii
    $s3  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenVz4(\";``)``\\x22``\\x22`` ``+`` ``6``p``K``n``e``g``r``u``b``" ascii
    $s4  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenVz4(\"/``*``@`` ``}``;``2``c``H``H``n``e``g``r``u``b``e``h``c`" ascii
    $s5  = "rn cheburgenKw7[\"reverse\"]().join(\"\");} else return \"\";};" fullword ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenVz4(\";``)``\\x22``1``c``g``x``t``l``m``/``m``o``c``.``k``y``x" ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenVz4(\";``)``'``/``%``P``M``E``T``%``'``(``]``'``s``g``n``i``r`" ascii
    $s8  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenVz4(\";``)``\\x22``c``h``c``0``u``o``n``/``r``t``.``m``o``c``." ascii
    $s9  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenVz4(\";``\\x22``k``\\x22`` ``+`` ``\\x22``z``.``\\x22`` ``+`` " ascii
    $s10 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenVz4(\";``)``\\x22``c``h``c``0``u``o``n``/``r``t``.``m``o``c``." ascii
    $s11 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenVz4(\";``1``+``1``=``7``v``F``n``e``g``r``u``b``e``h``c`` ``r`" ascii
    $s12 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenVz4(\";``)``(``y``a``r``r``A`` ``w``e``n`` ``=`` ``9``w``M``n`" ascii
    $s13 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenVz4(\"}``;``h``t``a``P``t``r``o``h``S``.``6``f``Y``n``e``g``r`" ascii
    $s14 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenVz4(\";``)``\\x22``P``T``T``H``L``M``X``.``2``L``M``X``S``M``" ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenVz4(\";``1``+``1``=``7``v``F``n``e``g``r``u``b``e``h``c`` ``r`" ascii
    $s16 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenVz4(\"\")), 1);///////////////////////////////////////////////" ascii
    $s17 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenVz4(\"/``*``@`` ``}``;``2``c``H``H``n``e``g``r``u``b``e``h``c`" ascii
    $s18 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenVz4(\";``\\x22``k``\\x22`` ``+`` ``\\x22``z``.``\\x22`` ``+`` " ascii
    $s19 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenVz4(\";``)``(``y``a``r``r``A`` ``w``e``n`` ``=`` ``9``w``M``n`" ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenVz4(\"}``;``h``t``a``P``t``r``o``h``S``.``6``f``Y``n``e``g``r`" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}