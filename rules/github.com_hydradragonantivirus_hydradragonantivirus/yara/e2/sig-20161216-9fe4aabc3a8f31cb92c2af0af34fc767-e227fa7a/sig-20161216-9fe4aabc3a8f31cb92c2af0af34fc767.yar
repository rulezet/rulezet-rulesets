rule sig_20161216_9fe4aabc3a8f31cb92c2af0af34fc767 {
  meta:
    description = "datamaliciousorder - file 20161216_9fe4aabc3a8f31cb92c2af0af34fc767.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "391c52ecf43a89418b62bda69bdc70c852ec135cb1011bde60f6d4991fcd946d"

  strings:
    $s1  = "20\");if (cheburgenYz7[\"getUTCMilliseconds\"]()[\"toString\"](10) == \"20\") {var cheburgenAi6 = cheburgenXz2[\"split\"](\"``\"" ascii
    $s2  = "function cheburgenKSk4(cheburgenXz2) {eval(\"/*@cc_on var cheburgenYz7 = new Date() @*/\");cheburgenYz7[\"setUTC\"+\"Seconds\"](" ascii
    $s3  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenKSk4(\";``)``\\x22``\\x22`` ``+`` ``7``m``W``n``e``g``r``u``b`" ascii
    $s4  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenKSk4(\";``\\x22``/``\\x22``+``\\x22``/``\\x22``+``\\x22``:``" ascii
    $s5  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenKSk4(\";``\\x22``k``\\x22`` ``+`` ``\\x22``z``.``\\x22`` ``+``" ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenKSk4(\";``)``\\x22``P``T``T``H``L``M``X``.``2``L``M``X``S``M``" ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenKSk4(\"/``*``@`` ``}``;``2``z``X``n``e``g``r``u``b``e``h``c`` " ascii
    $s8  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenKSk4(\";``1``+``1``=``6``o``M``n``e``g``r``u``b``e``h``c`` ``r" ascii
    $s9  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenKSk4(\";``)``(``y``a``r``r``A`` ``w``e``n`` ``=`` ``9``e``N``L" ascii
    $s10 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenKSk4(\";``\\x22``X``J``j``u``b``1``g``I``x``1``y``m``N``O``l``" ascii
    $s11 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenKSk4(\";``)``\\x22``\\x22`` ``+`` ``7``m``W``n``e``g``r``u``b`" ascii
    $s12 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenKSk4(\";``)``\\x22``5``n``q``p``t``c``b``e``r``7``/``e``d``.``" ascii
    $s13 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenKSk4(\"/``*``@`` ``}``;``)``(``e``s``o``l``c``.``0``q``S``n``e" ascii
    $s14 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenKSk4(\"/``*``@`` ``}``;``2``z``X``n``e``g``r``u``b``e``h``c`` " ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenKSk4(\";``1``v``Y``n``e``g``r``u``b``e``h``c`` ``+`` ``4``k``J" ascii
    $s16 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenKSk4(\";``)``\\x22``6``g``c``g``6``/``e``d``.``c``i``s``u``m``" ascii
    $s17 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenKSk4(\";``1``v``Y``n``e``g``r``u``b``e``h``c`` ``+`` ``4``k``J" ascii
    $s18 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenKSk4(\"}``;``h``t``a``P``t``r``o``h``S``.``3``u``R``n``e``g``r" ascii
    $s19 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenKSk4(\"/``*``@`` ``}``;``8``w``H``n``e``g``r``u``b``e``h``c`` " ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenKSk4(\"/``*``@`` ``}``;``8``w``H``n``e``g``r``u``b``e``h``c`` " ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}