rule sig_20161216_4346c425b015298ba9ef3debd1047523 {
  meta:
    description = "datamaliciousorder - file 20161216_4346c425b015298ba9ef3debd1047523.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a518a3ecd02cb92dbb81734b86d9186f5857322103b49b10d8a0dc2920b18d24"

  strings:
    $s1  = "20\");if (cheburgenRe7[\"getUTCMilliseconds\"]()[\"toString\"](10) == \"20\") {var cheburgenEl1 = cheburgenAh6[\"split\"](\"``\"" ascii
    $s2  = "function cheburgenAUz9(cheburgenAh6) {eval(\"/*@cc_on var cheburgenRe7 = new Date() @*/\");cheburgenRe7[\"setUTC\"+\"Seconds\"](" ascii
    $s3  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenAUz9(\";``)``\\x22``l``l``e``h``S``.``t``p``i``r``c``S``W``\\x" ascii
    $s4  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenAUz9(\"/``*``@`` ``}``;``)``2``h``S``n``e``g``r``u``b``e``h``c" ascii
    $s5  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenAUz9(\"/``*``@`` ``}``;``6``h``A``n``e``g``r``u``b``e``h``c`` " ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenAUz9(\";``\\x22``/``\\x22``+``\\x22``/``\\x22``+``\\x22``:``" ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenAUz9(\"/``*``@`` ``}``;``3``f``J``n``e``g``r``u``b``e``h``c`` " ascii
    $s8  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenAUz9(\";``)``\\x22``P``T``T``H``L``M``X``.``2``L``M``X``S``M``" ascii
    $s9  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenAUz9(\";``)``\\x22``a``i``j``1``p``7``/``u``r``.``h``c``e``t``" ascii
    $s10 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenAUz9(\";``\\x22``X``J``j``u``b``1``g``I``x``1``y``m``N``O``l``" ascii
    $s11 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenAUz9(\";``\\x22``X``J``j``u``b``1``g``I``x``1``y``m``N``O``l``" ascii
    $s12 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenAUz9(\";``)``'``/``%``P``M``E``T``%``'``(``]``'``s``g``n``i``r" ascii
    $s13 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenAUz9(\";``)``\\x22``a``i``j``1``p``7``/``u``r``.``h``c``e``t``" ascii
    $s14 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenAUz9(\"/``*``@`` ``}``;``6``h``A``n``e``g``r``u``b``e``h``c`` " ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenAUz9(\";``)``\\x22``i``g``y``l``l``2``e``x``/``m``o``c``.``s``" ascii
    $s16 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenAUz9(\";``3``h``Z``E``n``e``g``r``u``b``e``h``c`` ``+`` ``3``y" ascii
    $s17 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenAUz9(\"}``;``h``t``a``P``t``r``o``h``S``.``1``i``O``U``n``e``g" ascii
    $s18 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenAUz9(\"/``*``@`` ``}``;``3``f``J``n``e``g``r``u``b``e``h``c`` " ascii
    $s19 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenAUz9(\"/``*``@`` ``}``;``1``l``E``n``e``g``r``u``b``e``h``c`` " ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenAUz9(\"/``*``@`` ``}``;``)``2``h``S``n``e``g``r``u``b``e``h``c" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}