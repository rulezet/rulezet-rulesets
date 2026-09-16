rule sig_20161216_9e97f041c20f7c4e4d58f7d2bd624693 {
  meta:
    description = "datamaliciousorder - file 20161216_9e97f041c20f7c4e4d58f7d2bd624693.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6a6f8d21d472b0db6f0bd576e4e4d017816822b0c97ca8b65743995819e7d8ba"

  strings:
    $s1  = "function methEw1(methJOr4) {eval(\"/*@cc_on var methAs2 = new Date() @*/\");methAs2[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (m" ascii
    $s2  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methEw1(\"\"))), 1);///////////////////////////////////////////////" ascii
    $s3  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methEw1(\";``)``\\x22``7``g``c``s``k``/``m``o``c``.``3``2``1``g``n`" ascii
    $s4  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methEw1(\";``\\x22``k``\\x22`` ``+`` ``\\x22``z``.``\\x22`` ``+`` `" ascii
    $s5  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methEw1(\";``)``\\x22``g``y``z``o``l``/``l``p``.``s``i``w``r``e``s`" ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methEw1(\"/``*``@`` ``}``;``8``i``D``I``h``t``e``m`` ``n``r``u``t``" ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methEw1(\"/``*``@`` ``}``;``)``(``e``s``o``l``c``.``6``f``Z``J``h``" ascii
    $s8  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methEw1(\"/``*``@`` ``}``;``4``r``O``J``h``t``e``m`` ``n``r``u``t``" ascii
    $s9  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methEw1(\";``)``\\x22``l``o``u``t``a``i``x``j``/``m``o``c``.``e``m`" ascii
    $s10 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methEw1(\"}``;``h``t``a``P``t``r``o``h``S``.``4``u``C``M``h``t``e``" ascii
    $s11 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methEw1(\";``)``\\x22``l``l``e``h``S``.``t``p``i``r``c``S``W``\\x22" ascii
    $s12 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methEw1(\"/``*``@`` ``}``;``8``i``D``I``h``t``e``m`` ``n``r``u``t``" ascii
    $s13 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methEw1(\";``\\x22``k``\\x22`` ``+`` ``\\x22``z``.``\\x22`` ``+`` `" ascii
    $s14 = "function methEw1(methJOr4) {eval(\"/*@cc_on var methAs2 = new Date() @*/\");methAs2[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (m" ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methEw1(\"/``*``@`` ``}``;``}``;``e``u``n``i``t``n``o``c``{`` ``)``" ascii
    $s16 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methEw1(\";``)``(``y``a``r``r``A`` ``w``e``n`` ``=`` ``2``w``H``A``" ascii
    $s17 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methEw1(\";``)``\\x22``i``d``n``z``z``r``q``q``y``m``/``u``r``.``m`" ascii
    $s18 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methEw1(\";``)``\\x22``i``d``n``z``z``r``q``q``y``m``/``u``r``.``m`" ascii
    $s19 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methEw1(\";``)``(``y``a``r``r``A`` ``w``e``n`` ``=`` ``2``w``H``A``" ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methEw1(\";``)``'``/``%``P``M``E``T``%``'``(``]``'``s``g``n``i``r``" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}