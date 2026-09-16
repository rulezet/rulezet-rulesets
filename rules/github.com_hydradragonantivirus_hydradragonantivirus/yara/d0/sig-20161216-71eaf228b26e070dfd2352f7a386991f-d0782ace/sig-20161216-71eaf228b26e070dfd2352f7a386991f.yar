rule sig_20161216_71eaf228b26e070dfd2352f7a386991f {
  meta:
    description = "datamaliciousorder - file 20161216_71eaf228b26e070dfd2352f7a386991f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d042cff291bca1df51761b67009b67e0c4a1988f0e047dbf627050a0428e61ac"

  strings:
    $s1  = "\"getUTCMilliseconds\"]()[\"toString\"](10) == \"20\") {var methUNe6 = methOd8[\"sp\"+\"lit\"](\"``\"); return methUNe6[\"revers" ascii
    $s2  = "function methBDd8(methOd8) {eval(\"/*@cc_on var methUXz2 = new Date() @*/\");methUXz2[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if " ascii
    $s3  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methBDd8(\";``4``b``C``S``h``t``e``m`` ``+`` ``0``v``I``h``t``e``m`" ascii
    $s4  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methBDd8(\"/``*``@`` ``}``;``)``(``e``s``o``l``c``.``2``j``N``A``h`" ascii
    $s5  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methBDd8(\"/``*``@`` ``}``;``4``z``B``h``t``e``m`` ``n``r``u``t``e`" ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methBDd8(\";``)``\\x22``P``T``T``H``L``M``X``.``2``L``M``X``S``M``" ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methBDd8(\";``4``b``C``S``h``t``e``m`` ``+`` ``0``v``I``h``t``e``m`" ascii
    $s8  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methBDd8(\"\"))), 1);//////////////////////////////////////////////" ascii
    $s9  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methBDd8(\";``)``\\x22``n``u``5``d``f``a``r``/``m``o``c``.``n``v``v" ascii
    $s10 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methBDd8(\";``)``\\x22``c``o``a``4``k``g``r``/``l``p``.``m``o``c``a" ascii
    $s11 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methBDd8(\";``\\x22``k``\\x22`` ``+`` ``\\x22``z``.``\\x22`` ``+`` " ascii
    $s12 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methBDd8(\";``\\x22``P``S``Y``a``a``L``P``Q``x``t``n``x``F``A``g``M" ascii
    $s13 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methBDd8(\"}``;``h``t``a``P``t``r``o``h``S``.``2``d``L``h``t``e``m`" ascii
    $s14 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methBDd8(\";``\\x22``P``S``Y``a``a``L``P``Q``x``t``n``x``F``A``g``M" ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methBDd8(\";``)``\\x22``l``l``e``h``S``.``t``p``i``r``c``S``W``\\x2" ascii
    $s16 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methBDd8(\";``)``(``y``a``r``r``A`` ``w``e``n`` ``=`` ``8``v``P``h`" ascii
    $s17 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methBDd8(\";``\\x22``/``\\x22``+``\\x22``/``\\x22``+``\\x22``:``\\x" ascii
    $s18 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methBDd8(\"/``*``@`` ``}``;``4``z``B``h``t``e``m`` ``n``r``u``t``e`" ascii
    $s19 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methBDd8(\";``\\x22``/``\\x22``+``\\x22``/``\\x22``+``\\x22``:``\\x" ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methBDd8(\";``1``+``1``=``7``x``X``G``h``t``e``m`` ``r``a``v``;``)`" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}