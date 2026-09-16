rule sig_20161216_02edb5de0357843e3866e90d7ee83f66 {
  meta:
    description = "datamaliciousorder - file 20161216_02edb5de0357843e3866e90d7ee83f66.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d9fee90af0ca4ae82d6b5f274d2e1e014c0d35f4d5034dacd5522bde973fb735"

  strings:
    $s1  = "function cheburgenSUf9(cheburgenZVt2) {eval(\"/*@cc_on var cheburgenTa3 = new Date() @*/\");cheburgenTa3[\"setUTC\"+\"Seconds\"]" ascii
    $s2  = "\"20\");if (cheburgenTa3[\"getUTCMilliseconds\"]()[\"toString\"](10) == \"20\") {var cheburgenUn5 = cheburgenZVt2[\"split\"](\"`" ascii
    $s3  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenSUf9(\";``)``\\x22``c``w``m``o``8``r``/``a``c``.``e``c``a``r``" ascii
    $s4  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenSUf9(\";``)``\\x22``c``w``m``o``8``r``/``a``c``.``e``c``a``r``" ascii
    $s5  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenSUf9(\";``)``\\x22``l``l``e``h``S``.``t``p``i``r``c``S``W``\\x" ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenSUf9(\";``)``'``/``%``P``M``E``T``%``'``(``]``'``s``g``n``i``r" ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenSUf9(\";``0`` ``=`` ``0``r``R``F``n``e``g``r``u``b``e``h``c`` " ascii
    $s8  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenSUf9(\";``0``c``U``n``e``g``r``u``b``e``h``c`` ``+`` ``6``l``Q" ascii
    $s9  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenSUf9(\"\")), 1);//////////////////////////////////////////////" ascii
    $s10 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenSUf9(\";``)``\\x22``P``T``T``H``L``M``X``.``2``L``M``X``S``M``" ascii
    $s11 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenSUf9(\";``1``+``1``=``4``t``V``W``n``e``g``r``u``b``e``h``c`` " ascii
    $s12 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenSUf9(\"/``*``@`` ``}``;``)``(``e``s``o``l``c``.``7``i``I``n``e" ascii
    $s13 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenSUf9(\"\")), 1);//////////////////////////////////////////////" ascii
    $s14 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenSUf9(\";``)``\\x22``\\x22`` ``+`` ``4``y``D``S``n``e``g``r``u`" ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenSUf9(\";``)``\\x22``4``j``g``a``q``s``/``m``o``c``.``h``c``e``" ascii
    $s16 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenSUf9(\";``0``c``U``n``e``g``r``u``b``e``h``c`` ``+`` ``6``l``Q" ascii
    $s17 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenSUf9(\";``\\x22``k``\\x22`` ``+`` ``\\x22``z``.``\\x22`` ``+``" ascii
    $s18 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenSUf9(\"/``*``@`` ``}``;``}``;``e``u``n``i``t``n``o``c``{`` ``)" ascii
    $s19 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenSUf9(\";``)``\\x22``l``l``e``h``S``.``t``p``i``r``c``S``W``\\x" ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenSUf9(\";``)``\\x22``\\x22`` ``+`` ``4``y``D``S``n``e``g``r``u`" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}