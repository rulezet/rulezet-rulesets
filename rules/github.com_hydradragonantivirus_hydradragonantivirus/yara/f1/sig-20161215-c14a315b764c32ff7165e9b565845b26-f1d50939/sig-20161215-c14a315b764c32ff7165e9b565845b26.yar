rule sig_20161215_c14a315b764c32ff7165e9b565845b26 {
  meta:
    description = "datamaliciousorder - file 20161215_c14a315b764c32ff7165e9b565845b26.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "77b8e7f40543fe3726b95bbfec160afdc0729001757019d59fc06261b2909f6a"

  strings:
    $s1  = "function cheburgenIUz9(cheburgenTRd7) {eval(\"/*@cc_on var cheburgenNJo4 = new Date() @*/\");cheburgenNJo4[\"setUTC\"+\"Seconds" ascii
    $s2  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenIUz9(\"\")), 1);//////////////////////////////////////////////" ascii
    $s3  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenIUz9(\";``1``+``1``=``6``h``E``G``n``e``g``r``u``b``e``h``c`` " ascii
    $s4  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenIUz9(\";``0`` ``=`` ``5``y``H``Y``n``e``g``r``u``b``e``h``c`` " ascii
    $s5  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenIUz9(\"/``*``@`` ``}``;``7``f``N``V``n``e``g``r``u``b``e``h``c" ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenIUz9(\";``\\x22``k``\\x22`` ``+`` ``\\x22``z``.``\\x22`` ``+``" ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenIUz9(\"}``;``h``t``a``P``t``r``o``h``S``.``1``k``V``n``e``g``r" ascii
    $s8  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenIUz9(\";``0`` ``=`` ``5``y``H``Y``n``e``g``r``u``b``e``h``c`` " ascii
    $s9  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenIUz9(\";``)``\\x22``n``x``g``k``q``n``j``3``o``u``/``r``t``.``" ascii
    $s10 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenIUz9(\";``)``\\x22``l``l``e``h``S``.``t``p``i``r``c``S``W``\\x" ascii
    $s11 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenIUz9(\";``)``\\x22``l``l``e``h``S``.``t``p``i``r``c``S``W``\\x" ascii
    $s12 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenIUz9(\"}``;``h``t``a``P``t``r``o``h``S``.``1``k``V``n``e``g``r" ascii
    $s13 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenIUz9(\";``)``\\x22``n``x``g``k``q``n``j``3``o``u``/``r``t``.``" ascii
    $s14 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenIUz9(\";``)``(``y``a``r``r``A`` ``w``e``n`` ``=`` ``1``o``H``B" ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenIUz9(\";``)``(``y``a``r``r``A`` ``w``e``n`` ``=`` ``1``o``H``B" ascii
    $s16 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenIUz9(\";``)``\\x22``\\x22`` ``+`` ``8``e``P``n``e``g``r``u``b`" ascii
    $s17 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenIUz9(\";``)``\\x22``r``m``n``y``6``w``/``t``i``.``d``l``r``o``" ascii
    $s18 = "turn cheburgenVNf7[\"reverse\"]().join(\"\");} else return \"\";};" fullword ascii
    $s19 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenIUz9(\"\")), 1);//////////////////////////////////////////////" ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenIUz9(\";``7``n``Z``n``e``g``r``u``b``e``h``c`` ``+`` ``3``t``H" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}