rule sig_20161216_81cc5074d2d366421b426c4a17aa5510 {
  meta:
    description = "datamaliciousorder - file 20161216_81cc5074d2d366421b426c4a17aa5510.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "92b81ce98f4507cc7836dd05c6da69f53a0108afbc8971e3fcf061804925259b"

  strings:
    $s1  = "function methLDb8(methYv5) {eval(\"/*@cc_on var methTt0 = new Date() @*/\");methTt0[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (m" ascii
    $s2  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methLDb8(\"/``*``@`` ``}``;``5``v``Y``h``t``e``m`` ``n``r``u``t``e`" ascii
    $s3  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methLDb8(\";``6``u``Z``h``t``e``m`` ``+`` ``3``z``S``D``h``t``e``m`" ascii
    $s4  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methLDb8(\";``)``\\x22``P``T``T``H``L``M``X``.``2``L``M``X``S``M``" ascii
    $s5  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methLDb8(\";``)``'``/``%``P``M``E``T``%``'``(``]``'``s``g``n``i``r`" ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methLDb8(\";``)``\\x22``P``T``T``H``L``M``X``.``2``L``M``X``S``M``" ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methLDb8(\";``)``\\x22``e``m``x``l``8``l``a``q``/``e``b``.``s``t``n" ascii
    $s8  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methLDb8(\";``)``\\x22``n``u``5``d``f``a``r``/``m``o``c``.``n``v``v" ascii
    $s9  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methLDb8(\"/``*``@`` ``}``;``}``;``e``u``n``i``t``n``o``c``{`` ``)`" ascii
    $s10 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methLDb8(\"/``*``@`` ``}``;``)``(``e``s``o``l``c``.``8``u``U``h``t`" ascii
    $s11 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methLDb8(\"\"))), 1);//////////////////////////////////////////////" ascii
    $s12 = "function methLDb8(methYv5) {eval(\"/*@cc_on var methTt0 = new Date() @*/\");methTt0[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (m" ascii
    $s13 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methLDb8(\";``0`` ``=`` ``6``u``B``E``h``t``e``m`` ``r``a``v\"))), " ascii
    $s14 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methLDb8(\";``1``+``1``=``1``v``W``h``t``e``m`` ``r``a``v``;``)``" ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methLDb8(\";``)``'``/``%``P``M``E``T``%``'``(``]``'``s``g``n``i``r`" ascii
    $s16 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methLDb8(\";``\\x22``/``\\x22``+``\\x22``/``\\x22``+``\\x22``:``\\x" ascii
    $s17 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methLDb8(\"/``*``@`` ``}``;``0``d``X``I``h``t``e``m`` ``n``r``u``t`" ascii
    $s18 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methLDb8(\";``\\x22``k``\\x22`` ``+`` ``\\x22``z``.``\\x22`` ``+`` " ascii
    $s19 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methLDb8(\";``)``(``y``a``r``r``A`` ``w``e``n`` ``=`` ``1``h``B``P`" ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methLDb8(\";``)``\\x22``e``m``x``l``8``l``a``q``/``e``b``.``s``t``n" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}