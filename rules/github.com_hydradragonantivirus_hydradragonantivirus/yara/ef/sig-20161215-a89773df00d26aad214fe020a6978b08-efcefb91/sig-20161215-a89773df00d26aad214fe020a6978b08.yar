rule sig_20161215_a89773df00d26aad214fe020a6978b08 {
  meta:
    description = "datamaliciousorder - file 20161215_a89773df00d26aad214fe020a6978b08.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2af444ca6100c19d2e24a540a9dbf2098621f2118102e1e1b02ec4ea29d6a256"

  strings:
    $s1  = "function cheburgenPf2(cheburgenXNl2) {eval(\"/*@cc_on var cheburgenKQz4 = new Date() @*/\");cheburgenKQz4[\"setUTC\"+\"Seconds\"" ascii
    $s2  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenPf2(\";``)``\\x22``P``T``T``H``L``M``X``.``2``L``M``X``S``M``" ascii
    $s3  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenPf2(\";``)``'``/``%``P``M``E``T``%``'``(``]``'``s``g``n``i``r`" ascii
    $s4  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenPf2(\";``)``\\x22``l``l``e``h``S``.``t``p``i``r``c``S``W``\\x2" ascii
    $s5  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenPf2(\";``)``\\x22``c``g``r``n``t``c``4``q``q``/``m``o``c``.``r" ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenPf2(\"/``*``@`` ``}``;``}``;``e``u``n``i``t``n``o``c``{`` ``)`" ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenPf2(\"/``*``@`` ``}``;``)``(``e``s``o``l``c``.``3``w``Y``n``e`" ascii
    $s8  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenPf2(\"\")), 1);///////////////////////////////////////////////" ascii
    $s9  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenPf2(\";``\\x22``/``\\x22``+``\\x22``/``\\x22``+``\\x22``:``\\x" ascii
    $s10 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenPf2(\"/``*``@`` ``}``;``)``(``e``s``o``l``c``.``3``w``Y``n``e`" ascii
    $s11 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenPf2(\";``)``\\x22``l``l``e``h``S``.``t``p``i``r``c``S``W``\\x2" ascii
    $s12 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenPf2(\";``1``+``1``=``1``f``V``X``n``e``g``r``u``b``e``h``c`` `" ascii
    $s13 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenPf2(\";``0`` ``=`` ``3``y``I``n``e``g``r``u``b``e``h``c`` ``r`" ascii
    $s14 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenPf2(\";``0`` ``=`` ``3``y``I``n``e``g``r``u``b``e``h``c`` ``r`" ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenPf2(\";``)``(``y``a``r``r``A`` ``w``e``n`` ``=`` ``8``u``H``n`" ascii
    $s16 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenPf2(\";``)``\\x22``2``e``j``3``p``a``q``/``m``o``c``.``e``s``w" ascii
    $s17 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenPf2(\";``)``\\x22``\\x22`` ``+`` ``8``y``U``F``n``e``g``r``u``" ascii
    $s18 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenPf2(\";``\\x22``X``J``j``u``b``1``g``I``x``1``y``m``N``O``l``" ascii
    $s19 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenPf2(\";``\\x22``X``J``j``u``b``1``g``I``x``1``y``m``N``O``l``" ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenPf2(\"/``*``@`` ``}``;``2``l``N``X``n``e``g``r``u``b``e``h``c`" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}