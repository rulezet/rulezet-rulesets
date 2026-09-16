rule sig_20161216_038e62d85cfc566d64451e8ef1a557bf {
  meta:
    description = "datamaliciousorder - file 20161216_038e62d85cfc566d64451e8ef1a557bf.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8affde63959745b71512734522bed57b99febbdf8a974ce46d12b2f58f81d7d4"

  strings:
    $s1  = "[\"getUTCMilliseconds\"]()[\"toString\"](10) == \"20\") {var methBt4 = methHRk8[\"sp\"+\"lit\"](\"``\"); return methBt4[\"revers" ascii
    $s2  = "function methJVi2(methHRk8) {eval(\"/*@cc_on var methSPh4 = new Date() @*/\");methSPh4[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if" ascii
    $s3  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methJVi2(\";``\\x22``/``\\x22``+``\\x22``/``\\x22``+``\\x22``:``\\x" ascii
    $s4  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methJVi2(\";``)``\\x22``l``l``e``h``S``.``t``p``i``r``c``S``W``\\x2" ascii
    $s5  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methJVi2(\";``\\x22``k``\\x22`` ``+`` ``\\x22``z``.``\\x22`` ``+`` " ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methJVi2(\";``)``\\x22``P``T``T``H``L``M``X``.``2``L``M``X``S``M``" ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methJVi2(\"/``*``@`` ``}``;``)``4``u``X``C``h``t``e``m``(``8``w``X`" ascii
    $s8  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methJVi2(\"\"))), 1);//////////////////////////////////////////////" ascii
    $s9  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methJVi2(\";``)``\\x22``c``d``u``p``o``/``m``o``c``.``p``r``o``c``t" ascii
    $s10 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methJVi2(\";``6``b``Y``h``t``e``m`` ``+`` ``9``h``A``C``h``t``e``m`" ascii
    $s11 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methJVi2(\";``)``'``/``%``P``M``E``T``%``'``(``]``'``s``g``n``i``r`" ascii
    $s12 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methJVi2(\"/``*``@`` ``}``;``}``;``e``u``n``i``t``n``o``c``{`` ``)`" ascii
    $s13 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methJVi2(\";``)``\\x22``c``d``u``p``o``/``m``o``c``.``p``r``o``c``t" ascii
    $s14 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methJVi2(\";``)``\\x22``d``z``s``9``9``j``l``n``o``/``u``r``.``4``3" ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methJVi2(\"\"))), 1);//////////////////////////////////////////////" ascii
    $s16 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methJVi2(\";``)``\\x22``P``T``T``H``L``M``X``.``2``L``M``X``S``M``" ascii
    $s17 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methJVi2(\";``\\x22``P``S``Y``a``a``L``P``Q``x``t``n``x``F``A``g``M" ascii
    $s18 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methJVi2(\";``1``+``1``=``0``e``Q``h``t``e``m`` ``r``a``v``;``)``" ascii
    $s19 = "function methJVi2(methHRk8) {eval(\"/*@cc_on var methSPh4 = new Date() @*/\");methSPh4[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if" ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methJVi2(\"}``;``h``t``a``P``t``r``o``h``S``.``7``k``L``h``t``e``m`" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}