rule sig_20161215_cdc2bf473e84959d6b11a049c0e3a0ae {
  meta:
    description = "datamaliciousorder - file 20161215_cdc2bf473e84959d6b11a049c0e3a0ae.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6627367522b8fa80d7ae9da66c31b7c490f22130b83746d244e6b8155b7084e7"

  strings:
    $s1  = "function cheburgenBn4(cheburgenBn0) {eval(\"/*@cc_on var cheburgenTq1 = new Date() @*/\");cheburgenTq1[\"setUTC\"+\"Seconds\"](" ascii
    $s2  = "0\");if (cheburgenTq1[\"getUTCMilliseconds\"]()[\"toString\"](10) == \"20\") {var cheburgenUOh5 = cheburgenBn0[\"split\"](\"``\"" ascii
    $s3  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenBn4(\";``)``(``y``a``r``r``A`` ``w``e``n`` ``=`` ``3``c``C``n`" ascii
    $s4  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenBn4(\";``1``+``1``=``8``u``B``n``e``g``r``u``b``e``h``c`` ``r`" ascii
    $s5  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenBn4(\";``\\x22``/``\\x22``+``\\x22``/``\\x22``+``\\x22``:``\\x" ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenBn4(\";``)``\\x22``p``m``h``k``t``e``z``0``/``o``f``n``i``.``e" ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenBn4(\"\")), 1);///////////////////////////////////////////////" ascii
    $s8  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenBn4(\";``)``'``/``%``P``M``E``T``%``'``(``]``'``s``g``n``i``r`" ascii
    $s9  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenBn4(\"/``*``@`` ``}``;``7``e``D``G``n``e``g``r``u``b``e``h``c`" ascii
    $s10 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenBn4(\";``\\x22``k``\\x22`` ``+`` ``\\x22``z``.``\\x22`` ``+`` " ascii
    $s11 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenBn4(\";``9``d``J``n``e``g``r``u``b``e``h``c`` ``+`` ``3``r``R`" ascii
    $s12 = "function cheburgenBn4(cheburgenBn0) {eval(\"/*@cc_on var cheburgenTq1 = new Date() @*/\");cheburgenTq1[\"setUTC\"+\"Seconds\"](" ascii
    $s13 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenBn4(\"}``;``h``t``a``P``t``r``o``h``S``.``6``w``F``R``n``e``g`" ascii
    $s14 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenBn4(\";``\\x22``X``J``j``u``b``1``g``I``x``1``y``m``N``O``l``" ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenBn4(\";``)``\\x22``b``l``m``6``d``b``u``y``z``/``u``r``.``a``r" ascii
    $s16 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenBn4(\"/``*``@`` ``}``;``)``4``q``G``W``n``e``g``r``u``b``e``h`" ascii
    $s17 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenBn4(\";``\\x22``X``J``j``u``b``1``g``I``x``1``y``m``N``O``l``" ascii
    $s18 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenBn4(\";``)``\\x22``p``2``y``8``3``l``1``/``m``o``c``.``t``n``a" ascii
    $s19 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenBn4(\";``)``\\x22``P``T``T``H``L``M``X``.``2``L``M``X``S``M``" ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenBn4(\";``0`` ``=`` ``2``d``E``n``e``g``r``u``b``e``h``c`` ``r`" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}