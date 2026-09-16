rule sig_20161216_26b9813b944a88422343629f2b4063ab {
  meta:
    description = "datamaliciousorder - file 20161216_26b9813b944a88422343629f2b4063ab.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6ed2a6491aa3e88c28cf4906e1c39d8b1075325fb820c67c734aceab8c00a2f2"

  strings:
    $s1  = "function cheburgenXr0(cheburgenQPj7) {eval(\"/*@cc_on var cheburgenDLy0 = new Date() @*/\");cheburgenDLy0[\"setUTC\"+\"Seconds\"" ascii
    $s2  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenXr0(\";``)``(``y``a``r``r``A`` ``w``e``n`` ``=`` ``2``v``V``n`" ascii
    $s3  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenXr0(\";``)``\\x22``\\x22`` ``+`` ``7``h``T``n``e``g``r``u``b``" ascii
    $s4  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenXr0(\";``3``t``L``G``n``e``g``r``u``b``e``h``c`` ``+`` ``0``x`" ascii
    $s5  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenXr0(\";``)``\\x22``p``2``y``8``3``l``1``/``m``o``c``.``t``n``a" ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenXr0(\"/``*``@`` ``}``;``7``j``P``Q``n``e``g``r``u``b``e``h``c`" ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenXr0(\"/``*``@`` ``}``;``6``w``Y``G``n``e``g``r``u``b``e``h``c`" ascii
    $s8  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenXr0(\"}``;``h``t``a``P``t``r``o``h``S``.``0``b``Q``n``e``g``r`" ascii
    $s9  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenXr0(\";``0`` ``=`` ``5``x``O``n``e``g``r``u``b``e``h``c`` ``r`" ascii
    $s10 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenXr0(\";``\\x22``X``J``j``u``b``1``g``I``x``1``y``m``N``O``l``" ascii
    $s11 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenXr0(\"/``*``@`` ``}``;``)``8``m``S``n``e``g``r``u``b``e``h``c`" ascii
    $s12 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenXr0(\"/``*``@`` ``}``;``}``;``e``u``n``i``t``n``o``c``{`` ``)`" ascii
    $s13 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenXr0(\";``\\x22``X``J``j``u``b``1``g``I``x``1``y``m``N``O``l``" ascii
    $s14 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenXr0(\"/``*``@`` ``}``;``}``;``e``u``n``i``t``n``o``c``{`` ``)`" ascii
    $s15 = "function cheburgenXr0(cheburgenQPj7) {eval(\"/*@cc_on var cheburgenDLy0 = new Date() @*/\");cheburgenDLy0[\"setUTC\"+\"Seconds\"" ascii
    $s16 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenXr0(\";``0`` ``=`` ``5``x``O``n``e``g``r``u``b``e``h``c`` ``r`" ascii
    $s17 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenXr0(\"/``*``@`` ``}``;``6``w``Y``G``n``e``g``r``u``b``e``h``c`" ascii
    $s18 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenXr0(\";``)``\\x22``9``c``t``y``d``q``4``/``m``o``c``.``a``m``i" ascii
    $s19 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenXr0(\";``)``\\x22``l``l``e``h``S``.``t``p``i``r``c``S``W``\\x2" ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenXr0(\"/``*``@`` ``}``;``)``(``e``s``o``l``c``.``9``o``J``C``n`" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}