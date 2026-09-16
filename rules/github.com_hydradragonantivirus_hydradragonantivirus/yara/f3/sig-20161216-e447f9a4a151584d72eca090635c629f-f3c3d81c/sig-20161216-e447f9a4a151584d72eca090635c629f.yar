rule sig_20161216_e447f9a4a151584d72eca090635c629f {
  meta:
    description = "datamaliciousorder - file 20161216_e447f9a4a151584d72eca090635c629f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8cd6f40f9bb4f596e9ed7423e5e9c64e08795411705d2d3158d39bb369a32eb0"

  strings:
    $s1  = "getUTCMilliseconds\"]()[\"toString\"](10) == \"20\") {var methEy8 = methNb4[\"sp\"+\"lit\"](\"``\"); return methEy8[\"reverse\"]" ascii
    $s2  = "function methSi8(methNb4) {eval(\"/*@cc_on var methUFh4 = new Date() @*/\");methUFh4[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (" ascii
    $s3  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methSi8(\";``1``+``1``=``8``p``B``h``t``e``m`` ``r``a``v``;``)``\\x" ascii
    $s4  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methSi8(\"/``*``@`` ``}``;``)``4``m``W``N``h``t``e``m``(``3``j``C``" ascii
    $s5  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methSi8(\";``0`` ``=`` ``0``l``X``W``h``t``e``m`` ``r``a``v\"))), 1" ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methSi8(\";``\\x22``k``\\x22`` ``+`` ``\\x22``z``.``\\x22`` ``+`` `" ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methSi8(\";``\\x22``P``S``Y``a``a``L``P``Q``x``t``n``x``F``A``g``M`" ascii
    $s8  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methSi8(\";``0`` ``=`` ``0``l``X``W``h``t``e``m`` ``r``a``v\"))), 1" ascii
    $s9  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methSi8(\";``)``(``y``a``r``r``A`` ``w``e``n`` ``=`` ``4``q``O``N``" ascii
    $s10 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methSi8(\";``)``\\x22``l``l``e``h``S``.``t``p``i``r``c``S``W``\\x22" ascii
    $s11 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methSi8(\";``)``(``y``a``r``r``A`` ``w``e``n`` ``=`` ``4``q``O``N``" ascii
    $s12 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methSi8(\"/``*``@`` ``}``;``8``y``E``h``t``e``m`` ``n``r``u``t``e``" ascii
    $s13 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methSi8(\";``\\x22``P``S``Y``a``a``L``P``Q``x``t``n``x``F``A``g``M`" ascii
    $s14 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methSi8(\";``)``\\x22``c``m``c``s``p``5``w``6``c``/``m``o``c``.``n`" ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methSi8(\"/``*``@`` ``}``;``9``q``I``T``h``t``e``m`` ``n``r``u``t``" ascii
    $s16 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methSi8(\";``)``\\x22``d``v``c``t``f``/``z``c``.``y``n``i``t``e``l`" ascii
    $s17 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methSi8(\";``)``\\x22``P``T``T``H``L``M``X``.``2``L``M``X``S``M``" ascii
    $s18 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methSi8(\";``)``\\x22``v``d``g``j``k``b``a``c``y``/``m``o``c``.``s`" ascii
    $s19 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methSi8(\";``\\x22``/``\\x22``+``\\x22``/``\\x22``+``\\x22``:``\\x2" ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methSi8(\"\"))), 1);///////////////////////////////////////////////" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}