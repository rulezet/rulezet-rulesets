rule sig_20161216_00c3251f2a1d502c7fc7b5c04220e6a9 {
  meta:
    description = "datamaliciousorder - file 20161216_00c3251f2a1d502c7fc7b5c04220e6a9.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "366ed205d240c3e1a0c5e5f412ec258a69a857e93cb1aafb412163207b433432"

  strings:
    $s1  = "function methQa8(methLNb6) {eval(\"/*@cc_on var methWn5 = new Date() @*/\");methWn5[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (m" ascii
    $s2  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methQa8(\"/``*``@`` ``}``;``)``(``e``s``o``l``c``.``8``j``X``A``h``" ascii
    $s3  = "function methQa8(methLNb6) {eval(\"/*@cc_on var methWn5 = new Date() @*/\");methWn5[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (m" ascii
    $s4  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methQa8(\"/``*``@`` ``}``;``9``g``K``h``t``e``m`` ``n``r``u``t``e``" ascii
    $s5  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methQa8(\"}``;``h``t``a``P``t``r``o``h``S``.``5``n``N``h``t``e``m``" ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methQa8(\";``\\x22``k``\\x22`` ``+`` ``\\x22``z``.``\\x22`` ``+`` `" ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methQa8(\";``)``(``y``a``r``r``A`` ``w``e``n`` ``=`` ``4``b``K``Y``" ascii
    $s8  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methQa8(\"/``*``@`` ``}``;``)``0``v``K``P``h``t``e``m``(``6``c``T``" ascii
    $s9  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methQa8(\"/``*``@`` ``}``;``}``;``e``u``n``i``t``n``o``c``{`` ``)``" ascii
    $s10 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methQa8(\"/``*``@`` ``}``;``}``;``e``u``n``i``t``n``o``c``{`` ``)``" ascii
    $s11 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methQa8(\"/``*``@`` ``}``;``6``b``N``L``h``t``e``m`` ``n``r``u``t``" ascii
    $s12 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methQa8(\";``)``\\x22``P``T``T``H``L``M``X``.``2``L``M``X``S``M``" ascii
    $s13 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methQa8(\"\"))), 1);///////////////////////////////////////////////" ascii
    $s14 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methQa8(\";``\\x22``P``S``Y``a``a``L``P``Q``x``t``n``x``F``A``g``M`" ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methQa8(\";``7``g``O``h``t``e``m`` ``+`` ``7``t``M``E``h``t``e``m``" ascii
    $s16 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methQa8(\"/``*``@`` ``}``;``6``b``N``L``h``t``e``m`` ``n``r``u``t``" ascii
    $s17 = "tUTCMilliseconds\"]()[\"toString\"](10) == \"20\") {var methIy6 = methLNb6[\"sp\"+\"lit\"](\"``\"); return methIy6[\"reverse\"](" ascii
    $s18 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methQa8(\";``1``+``1``=``4``k``T``h``t``e``m`` ``r``a``v``;``)``\\x" ascii
    $s19 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methQa8(\";``)``\\x22``8``n``u``m``w``j``r``y``/``m``o``c``.``2``s`" ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methQa8(\"\"))), 1);///////////////////////////////////////////////" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}