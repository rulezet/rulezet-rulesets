rule sig_20161216_f2a68c93c58ab79064579769d7fdc96a {
  meta:
    description = "datamaliciousorder - file 20161216_f2a68c93c58ab79064579769d7fdc96a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7cbf71cd0a1e8bc631ed0cfdaaaf7bde36414ca707e7a5809066e66be0972073"

  strings:
    $s1  = "function methLPt6(methPb9) {eval(\"/*@cc_on var methQu8 = new Date() @*/\");methQu8[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (m" ascii
    $s2  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methLPt6(\"\"))), 1);//////////////////////////////////////////////" ascii
    $s3  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methLPt6(\";``)``\\x22``u``t``o``w``i``u``0``v``/``u``r``.``r``a``c" ascii
    $s4  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methLPt6(\";``)``\\x22``w``t``n``g``c``r``s``u``/``m``o``c``.``o``n" ascii
    $s5  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methLPt6(\";``)``\\x22``w``t``n``g``c``r``s``u``/``m``o``c``.``o``n" ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methLPt6(\"/``*``@`` ``}``;``9``d``X``J``h``t``e``m`` ``n``r``u``t`" ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methLPt6(\";``0`` ``=`` ``4``v``J``F``h``t``e``m`` ``r``a``v\"))), " ascii
    $s8  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methLPt6(\";``0``g``H``O``h``t``e``m`` ``+`` ``6``p``R``h``t``e``m`" ascii
    $s9  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methLPt6(\"/``*``@`` ``}``;``9``z``C``K``h``t``e``m`` ``n``r``u``t`" ascii
    $s10 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methLPt6(\";``\\x22``P``S``Y``a``a``L``P``Q``x``t``n``x``F``A``g``M" ascii
    $s11 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methLPt6(\";``)``\\x22``e``m``i``j``f``t``u``u``/``m``o``c``.``o``i" ascii
    $s12 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methLPt6(\";``0``g``H``O``h``t``e``m`` ``+`` ``6``p``R``h``t``e``m`" ascii
    $s13 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methLPt6(\"/``*``@`` ``}``;``9``b``P``h``t``e``m`` ``n``r``u``t``e`" ascii
    $s14 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methLPt6(\";``)``\\x22``e``m``i``j``f``t``u``u``/``m``o``c``.``o``i" ascii
    $s15 = "function methLPt6(methPb9) {eval(\"/*@cc_on var methQu8 = new Date() @*/\");methQu8[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (m" ascii
    $s16 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methLPt6(\";``)``\\x22``g``m``k``6``n``c``o``k``e``w``/``m``o``c``." ascii
    $s17 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methLPt6(\";``)``'``/``%``P``M``E``T``%``'``(``]``'``s``g``n``i``r`" ascii
    $s18 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methLPt6(\";``)``\\x22``g``m``k``6``n``c``o``k``e``w``/``m``o``c``." ascii
    $s19 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methLPt6(\";``\\x22``k``\\x22`` ``+`` ``\\x22``z``.``\\x22`` ``+`` " ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methLPt6(\"/``*``@`` ``}``;``)``(``e``s``o``l``c``.``6``s``J``Q``h`" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}