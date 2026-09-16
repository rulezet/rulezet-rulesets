rule sig_20161216_58453b4d06913e85af7b868b4cabfa94 {
  meta:
    description = "datamaliciousorder - file 20161216_58453b4d06913e85af7b868b4cabfa94.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a06c1a4fcb6cab2750310beeeea4632d11a3e17ae2485ef138716be382ef3294"

  strings:
    $s1  = "0\");if (cheburgenMs4[\"getUTCMilliseconds\"]()[\"toString\"](10) == \"20\") {var cheburgenIv3 = cheburgenEu1[\"split\"](\"``\")" ascii
    $s2  = "function cheburgenSc3(cheburgenEu1) {eval(\"/*@cc_on var cheburgenMs4 = new Date() @*/\");cheburgenMs4[\"setUTC\"+\"Seconds\"](" ascii
    $s3  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenSc3(\"}``;``h``t``a``P``t``r``o``h``S``.``5``b``O``I``n``e``g`" ascii
    $s4  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenSc3(\";``\\x22``k``\\x22`` ``+`` ``\\x22``z``.``\\x22`` ``+`` " ascii
    $s5  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenSc3(\"/``*``@`` ``}``;``}``;``e``u``n``i``t``n``o``c``{`` ``)`" ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenSc3(\";``1``+``1``=``1``x``O``Y``n``e``g``r``u``b``e``h``c`` `" ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenSc3(\";``)``(``y``a``r``r``A`` ``w``e``n`` ``=`` ``1``o``G``n`" ascii
    $s8  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenSc3(\";``)``(``y``a``r``r``A`` ``w``e``n`` ``=`` ``1``o``G``n`" ascii
    $s9  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenSc3(\"/``*``@`` ``}``;``3``v``I``n``e``g``r``u``b``e``h``c`` `" ascii
    $s10 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenSc3(\"}``;``h``t``a``P``t``r``o``h``S``.``5``b``O``I``n``e``g`" ascii
    $s11 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenSc3(\";``0`` ``=`` ``4``o``Y``n``e``g``r``u``b``e``h``c`` ``r`" ascii
    $s12 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenSc3(\";``)``'``/``%``P``M``E``T``%``'``(``]``'``s``g``n``i``r`" ascii
    $s13 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenSc3(\";``\\x22``X``J``j``u``b``1``g``I``x``1``y``m``N``O``l``" ascii
    $s14 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenSc3(\";``)``\\x22``P``T``T``H``L``M``X``.``2``L``M``X``S``M``" ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenSc3(\";``7``f``Y``n``e``g``r``u``b``e``h``c`` ``+`` ``8``j``S`" ascii
    $s16 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenSc3(\";``)``\\x22``b``8``d``d``d``q``p``n``/``e``c``a``s``l``a" ascii
    $s17 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenSc3(\";``)``\\x22``m``e``k``k``8``u``o``/``m``o``c``.``s``n``o" ascii
    $s18 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenSc3(\";``\\x22``/``\\x22``+``\\x22``/``\\x22``+``\\x22``:``\\x" ascii
    $s19 = "function cheburgenSc3(cheburgenEu1) {eval(\"/*@cc_on var cheburgenMs4 = new Date() @*/\");cheburgenMs4[\"setUTC\"+\"Seconds\"](" ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenSc3(\"/``*``@`` ``}``;``1``u``E``n``e``g``r``u``b``e``h``c`` `" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}