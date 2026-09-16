rule sig_20161216_0637ada6ee273b43e214e48dffe71401 {
  meta:
    description = "datamaliciousorder - file 20161216_0637ada6ee273b43e214e48dffe71401.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f0af46aa94b8b91d8ee49a83afc35099fb94b029c9d7b66c880b13153add3330"

  strings:
    $s1  = "\"getUTCMilliseconds\"]()[\"toString\"](10) == \"20\") {var methTo0 = methWTh9[\"sp\"+\"lit\"](\"``\"); return methTo0[\"reverse" ascii
    $s2  = "function methKs4(methWTh9) {eval(\"/*@cc_on var methNLd9 = new Date() @*/\");methNLd9[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if " ascii
    $s3  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methKs4(\";``5``j``Z``M``h``t``e``m`` ``+`` ``7``t``X``h``t``e``m``" ascii
    $s4  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methKs4(\"/``*``@`` ``}``;``)``(``e``s``o``l``c``.``8``k``L``h``t``" ascii
    $s5  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methKs4(\"/``*``@`` ``}``;``7``k``A``S``h``t``e``m`` ``n``r``u``t``" ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methKs4(\"/``*``@`` ``}``;``}``;``e``u``n``i``t``n``o``c``{`` ``)``" ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methKs4(\";``1``+``1``=``6``q``U``N``h``t``e``m`` ``r``a``v``;``)``" ascii
    $s8  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methKs4(\";``)``\\x22``q``g``p``l``c``i``d``g``/``r``i``.``i``h``g`" ascii
    $s9  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methKs4(\";``0`` ``=`` ``6``t``I``h``t``e``m`` ``r``a``v\"))), 1);/" ascii
    $s10 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methKs4(\"\"))), 1);///////////////////////////////////////////////" ascii
    $s11 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methKs4(\"/``*``@`` ``}``;``)``2``i``B``h``t``e``m``(``5``a``M``h``" ascii
    $s12 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methKs4(\";``)``'``/``%``P``M``E``T``%``'``(``]``'``s``g``n``i``r``" ascii
    $s13 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methKs4(\";``1``+``1``=``6``q``U``N``h``t``e``m`` ``r``a``v``;``)``" ascii
    $s14 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methKs4(\";``)``\\x22``P``T``T``H``L``M``X``.``2``L``M``X``S``M``" ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methKs4(\";``5``j``Z``M``h``t``e``m`` ``+`` ``7``t``X``h``t``e``m``" ascii
    $s16 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methKs4(\"/``*``@`` ``}``;``9``h``T``W``h``t``e``m`` ``n``r``u``t``" ascii
    $s17 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methKs4(\";``\\x22``P``S``Y``a``a``L``P``Q``x``t``n``x``F``A``g``M`" ascii
    $s18 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methKs4(\";``\\x22``k``\\x22`` ``+`` ``\\x22``z``.``\\x22`` ``+`` `" ascii
    $s19 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methKs4(\";``)``\\x22``q``g``p``l``c``i``d``g``/``r``i``.``i``h``g`" ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methKs4(\";``\\x22``k``\\x22`` ``+`` ``\\x22``z``.``\\x22`` ``+`` `" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}