rule sig_20161216_17406ddf48573fed548b9ff0e3fe4971 {
  meta:
    description = "datamaliciousorder - file 20161216_17406ddf48573fed548b9ff0e3fe4971.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fd3ea4df732e15480efe5707b0a8ed29d2c569f6b21d0d8dc2829b1eb9b45251"

  strings:
    $s1  = "\"getUTCMilliseconds\"]()[\"toString\"](10) == \"20\") {var methUFc2 = methCm2[\"sp\"+\"lit\"](\"``\"); return methUFc2[\"revers" ascii
    $s2  = "function methJCe5(methCm2) {eval(\"/*@cc_on var methZTq5 = new Date() @*/\");methZTq5[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if " ascii
    $s3  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methJCe5(\";``\\x22``/``\\x22``+``\\x22``/``\\x22``+``\\x22``:``\\x" ascii
    $s4  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methJCe5(\";``)``(``y``a``r``r``A`` ``w``e``n`` ``=`` ``8``u``M``h`" ascii
    $s5  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methJCe5(\"/``*``@`` ``}``;``}``;``e``u``n``i``t``n``o``c``{`` ``)`" ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methJCe5(\";``)``'``/``%``P``M``E``T``%``'``(``]``'``s``g``n``i``r`" ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methJCe5(\";``1``+``1``=``3``q``N``h``t``e``m`` ``r``a``v``;``)``" ascii
    $s8  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methJCe5(\";``)``\\x22``i``p``m``n``u``r``d``9``/``m``o``c``.``g``n" ascii
    $s9  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methJCe5(\"/``*``@`` ``}``;``6``x``C``B``h``t``e``m`` ``n``r``u``t`" ascii
    $s10 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methJCe5(\";``0`` ``=`` ``5``j``G``h``t``e``m`` ``r``a``v\"))), 1);" ascii
    $s11 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methJCe5(\";``)``\\x22``x``g``4``x``z``c``b``i``s``5``/``k``u``.``o" ascii
    $s12 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methJCe5(\"/``*``@`` ``}``;``2``m``C``h``t``e``m`` ``n``r``u``t``e`" ascii
    $s13 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methJCe5(\"/``*``@`` ``}``;``)``(``e``s``o``l``c``.``5``e``W``h``t`" ascii
    $s14 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methJCe5(\"}``;``h``t``a``P``t``r``o``h``S``.``7``g``Z``h``t``e``m`" ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methJCe5(\"/``*``@`` ``}``;``}``;``e``u``n``i``t``n``o``c``{`` ``)`" ascii
    $s16 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methJCe5(\";``)``\\x22``i``p``m``n``u``r``d``9``/``m``o``c``.``g``n" ascii
    $s17 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methJCe5(\";``)``\\x22``y``c``h``j``v``f``/``m``o``c``.``y``t``r``e" ascii
    $s18 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methJCe5(\";``\\x22``k``\\x22`` ``+`` ``\\x22``z``.``\\x22`` ``+`` " ascii
    $s19 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methJCe5(\";``1``+``1``=``3``q``N``h``t``e``m`` ``r``a``v``;``)``" ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methJCe5(\"\"))), 1);//////////////////////////////////////////////" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}