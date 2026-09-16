rule sig_20161216_703c1f547b2639125d63ff9a0d5f0ff4 {
  meta:
    description = "datamaliciousorder - file 20161216_703c1f547b2639125d63ff9a0d5f0ff4.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3459b7846baad7163c4016cf30ff88ed57d33685b43688a1fe39748498eff257"

  strings:
    $s1  = "function cheburgenXSv9(cheburgenELg3) {eval(\"/*@cc_on var cheburgenLd5 = new Date() @*/\");cheburgenLd5[\"setUTC\"+\"Seconds\"]" ascii
    $s2  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenXSv9(\"/``*``@`` ``}``;``)``(``e``s``o``l``c``.``3``u``V``Z``n" ascii
    $s3  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenXSv9(\";``)``(``y``a``r``r``A`` ``w``e``n`` ``=`` ``0``q``D``A" ascii
    $s4  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenXSv9(\"/``*``@`` ``}``;``}``;``e``u``n``i``t``n``o``c``{`` ``)" ascii
    $s5  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenXSv9(\"/``*``@`` ``}``;``3``g``L``E``n``e``g``r``u``b``e``h``c" ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenXSv9(\"\")), 1);//////////////////////////////////////////////" ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenXSv9(\";``)``\\x22``x``s``m``3``o``9``h``/``m``o``c``.``m``i``" ascii
    $s8  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenXSv9(\"/``*``@`` ``}``;``}``;``e``u``n``i``t``n``o``c``{`` ``)" ascii
    $s9  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenXSv9(\";``0`` ``=`` ``2``z``A``n``e``g``r``u``b``e``h``c`` ``r" ascii
    $s10 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenXSv9(\"/``*``@`` ``}``;``1``s``V``G``n``e``g``r``u``b``e``h``c" ascii
    $s11 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenXSv9(\"/``*``@`` ``}``;``)``0``y``Y``A``n``e``g``r``u``b``e``h" ascii
    $s12 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenXSv9(\";``)``\\x22``x``s``m``3``o``9``h``/``m``o``c``.``m``i``" ascii
    $s13 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenXSv9(\";``8``f``U``G``n``e``g``r``u``b``e``h``c`` ``+`` ``6``c" ascii
    $s14 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenXSv9(\";``1``+``1``=``5``x``V``n``e``g``r``u``b``e``h``c`` ``r" ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenXSv9(\"/``*``@`` ``}``;``3``g``L``E``n``e``g``r``u``b``e``h``c" ascii
    $s16 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenXSv9(\";``)``\\x22``l``l``e``h``S``.``t``p``i``r``c``S``W``\\x" ascii
    $s17 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenXSv9(\";``\\x22``X``J``j``u``b``1``g``I``x``1``y``m``N``O``l``" ascii
    $s18 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenXSv9(\";``)``\\x22``i``g``y``l``l``2``e``x``/``m``o``c``.``s``" ascii
    $s19 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenXSv9(\";``\\x22``k``\\x22`` ``+`` ``\\x22``z``.``\\x22`` ``+``" ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenXSv9(\";``0`` ``=`` ``2``z``A``n``e``g``r``u``b``e``h``c`` ``r" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}