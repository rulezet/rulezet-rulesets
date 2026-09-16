rule sig_20161216_9ceb2e1134b4ad64cbbbf7013622acac {
  meta:
    description = "datamaliciousorder - file 20161216_9ceb2e1134b4ad64cbbbf7013622acac.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a1eda645b1886133b9259ca7ebcdb869298863aebd3669a48c77a1c12d7e4292"

  strings:
    $s1  = "function cheburgenAIf3(cheburgenNUe5) {eval(\"/*@cc_on var cheburgenAGu4 = new Date() @*/\");cheburgenAGu4[\"setUTC\"+\"Seconds" ascii
    $s2  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenAIf3(\";``\\x22``k``\\x22`` ``+`` ``\\x22``z``.``\\x22`` ``+``" ascii
    $s3  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenAIf3(\";``)``\\x22``e``0``9``k``s``i``/``p``o``t``.``e``s``i``" ascii
    $s4  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenAIf3(\";``)``(``y``a``r``r``A`` ``w``e``n`` ``=`` ``3``o``C``n" ascii
    $s5  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenAIf3(\"/``*``@`` ``}``;``)``(``e``s``o``l``c``.``9``n``Q``X``n" ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenAIf3(\"}``;``h``t``a``P``t``r``o``h``S``.``1``q``Y``n``e``g``r" ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenAIf3(\"/``*``@`` ``}``;``6``o``N``n``e``g``r``u``b``e``h``c`` " ascii
    $s8  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenAIf3(\";``0`` ``=`` ``6``t``O``W``n``e``g``r``u``b``e``h``c`` " ascii
    $s9  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenAIf3(\";``\\x22``X``J``j``u``b``1``g``I``x``1``y``m``N``O``l``" ascii
    $s10 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenAIf3(\"}``;``h``t``a``P``t``r``o``h``S``.``1``q``Y``n``e``g``r" ascii
    $s11 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenAIf3(\";``1``+``1``=``7``p``P``K``n``e``g``r``u``b``e``h``c`` " ascii
    $s12 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenAIf3(\";``)``\\x22``l``l``e``h``S``.``t``p``i``r``c``S``W``\\x" ascii
    $s13 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenAIf3(\";``4``l``D``n``e``g``r``u``b``e``h``c`` ``+`` ``9``x``T" ascii
    $s14 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenAIf3(\";``)``\\x22``a``i``j``1``p``7``/``u``r``.``h``c``e``t``" ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenAIf3(\";``\\x22``/``\\x22``+``\\x22``/``\\x22``+``\\x22``:``" ascii
    $s16 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenAIf3(\";``4``l``D``n``e``g``r``u``b``e``h``c`` ``+`` ``9``x``T" ascii
    $s17 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenAIf3(\";``)``\\x22``\\x22`` ``+`` ``1``b``T``n``e``g``r``u``b`" ascii
    $s18 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenAIf3(\"/``*``@`` ``}``;``)``1``p``C``n``e``g``r``u``b``e``h``c" ascii
    $s19 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenAIf3(\";``)``\\x22``P``T``T``H``L``M``X``.``2``L``M``X``S``M``" ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenAIf3(\";``0`` ``=`` ``6``t``O``W``n``e``g``r``u``b``e``h``c`` " ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}