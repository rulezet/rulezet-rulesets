rule sig_20161216_5bedb2473918a4752e01bc253a0ea582 {
  meta:
    description = "datamaliciousorder - file 20161216_5bedb2473918a4752e01bc253a0ea582.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "bd286eb4c99ec55ac28657c5e1c129e421929f7330eaab51ea30b764cfd4a959"

  strings:
    $s1  = "function cheburgenSQc0(cheburgenKRz5) {eval(\"/*@cc_on var cheburgenMEt9 = new Date() @*/\");cheburgenMEt9[\"setUTC\"+\"Seconds" ascii
    $s2  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenSQc0(\"/``*``@`` ``}``;``1``v``Y``A``n``e``g``r``u``b``e``h``c" ascii
    $s3  = "urn cheburgenCc0[\"reverse\"]().join(\"\");} else return \"\";};" fullword ascii
    $s4  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenSQc0(\"/``*``@`` ``}``;``5``z``R``K``n``e``g``r``u``b``e``h``c" ascii
    $s5  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenSQc0(\";``4``u``P``H``n``e``g``r``u``b``e``h``c`` ``+`` ``7``z" ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenSQc0(\";``0`` ``=`` ``3``g``D``N``n``e``g``r``u``b``e``h``c`` " ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenSQc0(\"\")), 1);//////////////////////////////////////////////" ascii
    $s8  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenSQc0(\"/``*``@`` ``}``;``)``0``p``E``n``e``g``r``u``b``e``h``c" ascii
    $s9  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenSQc0(\"/``*``@`` ``}``;``}``;``e``u``n``i``t``n``o``c``{`` ``)" ascii
    $s10 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenSQc0(\";``)``\\x22``p``v``r``k``l``3``9``w``0``q``/``m``o``c``" ascii
    $s11 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenSQc0(\";``)``'``/``%``P``M``E``T``%``'``(``]``'``s``g``n``i``r" ascii
    $s12 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenSQc0(\";``)``(``y``a``r``r``A`` ``w``e``n`` ``=`` ``5``e``Q``n" ascii
    $s13 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenSQc0(\";``\\x22``/``\\x22``+``\\x22``/``\\x22``+``\\x22``:``" ascii
    $s14 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenSQc0(\";``)``'``/``%``P``M``E``T``%``'``(``]``'``s``g``n``i``r" ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenSQc0(\"}``;``h``t``a``P``t``r``o``h``S``.``7``r``G``n``e``g``r" ascii
    $s16 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenSQc0(\";``)``\\x22``P``T``T``H``L``M``X``.``2``L``M``X``S``M``" ascii
    $s17 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenSQc0(\";``)``\\x22``l``l``e``h``S``.``t``p``i``r``c``S``W``\\x" ascii
    $s18 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenSQc0(\";``1``+``1``=``1``h``W``n``e``g``r``u``b``e``h``c`` ``r" ascii
    $s19 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenSQc0(\";``0`` ``=`` ``3``g``D``N``n``e``g``r``u``b``e``h``c`` " ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenSQc0(\";``)``\\x22``P``T``T``H``L``M``X``.``2``L``M``X``S``M``" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}