rule sig_20161216_7df16ff5524254192d7c29cbb076eaf3 {
  meta:
    description = "datamaliciousorder - file 20161216_7df16ff5524254192d7c29cbb076eaf3.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7e4acb5a60c4d764dfdf2479e6c7d82e2f710c8f2b0af0851249e663acab61f5"

  strings:
    $s1  = "function cheburgenIBs8(cheburgenDRi1) {eval(\"/*@cc_on var cheburgenEz6 = new Date() @*/\");cheburgenEz6[\"setUTC\"+\"Seconds\"]" ascii
    $s2  = "\"20\");if (cheburgenEz6[\"getUTCMilliseconds\"]()[\"toString\"](10) == \"20\") {var cheburgenNt5 = cheburgenDRi1[\"split\"](\"`" ascii
    $s3  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenIBs8(\"/``*``@`` ``}``;``)``(``e``s``o``l``c``.``5``d``K``n``e" ascii
    $s4  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenIBs8(\";``\\x22``/``\\x22``+``\\x22``/``\\x22``+``\\x22``:``" ascii
    $s5  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenIBs8(\";``0`` ``=`` ``5``p``C``A``n``e``g``r``u``b``e``h``c`` " ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenIBs8(\"/``*``@`` ``}``;``1``i``R``D``n``e``g``r``u``b``e``h``c" ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenIBs8(\";``)``\\x22``o``b``q``q``z``v``h``d``/``u``r``.``5``t``" ascii
    $s8  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenIBs8(\";``)``\\x22``d``q``j``4``d``u``/``m``o``c``.``d``n``a``" ascii
    $s9  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenIBs8(\";``1``+``1``=``3``m``J``n``e``g``r``u``b``e``h``c`` ``r" ascii
    $s10 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenIBs8(\";``)``\\x22``P``T``T``H``L``M``X``.``2``L``M``X``S``M``" ascii
    $s11 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenIBs8(\";``)``(``y``a``r``r``A`` ``w``e``n`` ``=`` ``0``x``H``M" ascii
    $s12 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenIBs8(\";``)``\\x22``7``u``l``k``m``/``m``o``c``.``i``h``s``o``" ascii
    $s13 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenIBs8(\";``)``'``/``%``P``M``E``T``%``'``(``]``'``s``g``n``i``r" ascii
    $s14 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenIBs8(\";``\\x22``k``\\x22`` ``+`` ``\\x22``z``.``\\x22`` ``+``" ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenIBs8(\"/``*``@`` ``}``;``7``f``U``V``n``e``g``r``u``b``e``h``c" ascii
    $s16 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenIBs8(\"}``;``h``t``a``P``t``r``o``h``S``.``1``s``J``n``e``g``r" ascii
    $s17 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenIBs8(\";``0`` ``=`` ``5``p``C``A``n``e``g``r``u``b``e``h``c`` " ascii
    $s18 = "function cheburgenIBs8(cheburgenDRi1) {eval(\"/*@cc_on var cheburgenEz6 = new Date() @*/\");cheburgenEz6[\"setUTC\"+\"Seconds\"]" ascii
    $s19 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenIBs8(\"/``*``@`` ``}``;``1``i``R``D``n``e``g``r``u``b``e``h``c" ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenIBs8(\"/``*``@`` ``}``;``)``0``i``G``Q``n``e``g``r``u``b``e``h" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}