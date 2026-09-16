rule sig_20161215_c0fca48484eb9f910addc051b0f8e6ef {
  meta:
    description = "datamaliciousorder - file 20161215_c0fca48484eb9f910addc051b0f8e6ef.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "29b0401ef176c1a91c48c5f2be2642f0797660b8e32ad9f0b8cf53617e3df3b6"

  strings:
    $s1  = "function cheburgenTQn4(cheburgenKJp9) {eval(\"/*@cc_on var cheburgenTw2 = new Date() @*/\");cheburgenTw2[\"setUTC\"+\"Seconds\"]" ascii
    $s2  = "\"20\");if (cheburgenTw2[\"getUTCMilliseconds\"]()[\"toString\"](10) == \"20\") {var cheburgenBm5 = cheburgenKJp9[\"split\"](\"`" ascii
    $s3  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenTQn4(\";``)``\\x22``l``l``e``h``S``.``t``p``i``r``c``S``W``\\x" ascii
    $s4  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenTQn4(\"/``*``@`` ``}``;``)``0``j``S``Y``n``e``g``r``u``b``e``h" ascii
    $s5  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenTQn4(\";``)``\\x22``m``e``k``k``8``u``o``/``m``o``c``.``s``n``" ascii
    $s6  = "function cheburgenTQn4(cheburgenKJp9) {eval(\"/*@cc_on var cheburgenTw2 = new Date() @*/\");cheburgenTw2[\"setUTC\"+\"Seconds\"]" ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenTQn4(\";``)``\\x22``g``c``w``h``p``/``a``u``.``m``o``c``.``z``" ascii
    $s8  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenTQn4(\";``)``(``y``a``r``r``A`` ``w``e``n`` ``=`` ``6``v``F``S" ascii
    $s9  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenTQn4(\";``)``\\x22``P``T``T``H``L``M``X``.``2``L``M``X``S``M``" ascii
    $s10 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenTQn4(\";``)``\\x22``l``l``e``h``S``.``t``p``i``r``c``S``W``\\x" ascii
    $s11 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenTQn4(\";``\\x22``k``\\x22`` ``+`` ``\\x22``z``.``\\x22`` ``+``" ascii
    $s12 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenTQn4(\"/``*``@`` ``}``;``5``m``B``n``e``g``r``u``b``e``h``c`` " ascii
    $s13 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenTQn4(\";``\\x22``/``\\x22``+``\\x22``/``\\x22``+``\\x22``:``" ascii
    $s14 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenTQn4(\";``\\x22``X``J``j``u``b``1``g``I``x``1``y``m``N``O``l``" ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenTQn4(\";``6``b``V``D``n``e``g``r``u``b``e``h``c`` ``+`` ``2``d" ascii
    $s16 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenTQn4(\"/``*``@`` ``}``;``4``x``R``G``n``e``g``r``u``b``e``h``c" ascii
    $s17 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenTQn4(\"}``;``h``t``a``P``t``r``o``h``S``.``2``m``U``n``e``g``r" ascii
    $s18 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenTQn4(\"}``;``h``t``a``P``t``r``o``h``S``.``2``m``U``n``e``g``r" ascii
    $s19 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenTQn4(\";``)``'``/``%``P``M``E``T``%``'``(``]``'``s``g``n``i``r" ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenTQn4(\";``)``\\x22``P``T``T``H``L``M``X``.``2``L``M``X``S``M``" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}