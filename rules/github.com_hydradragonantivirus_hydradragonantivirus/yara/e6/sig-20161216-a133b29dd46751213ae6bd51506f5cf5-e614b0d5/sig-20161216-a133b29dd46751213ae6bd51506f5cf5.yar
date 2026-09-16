rule sig_20161216_a133b29dd46751213ae6bd51506f5cf5 {
  meta:
    description = "datamaliciousorder - file 20161216_a133b29dd46751213ae6bd51506f5cf5.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e1fa02e95f78653ab70edf871756f2666e77ba04f8f798311e0ebd9deccf7a0d"

  strings:
    $s1  = "function methJYd5(methEh3) {eval(\"/*@cc_on var methBb8 = new Date() @*/\");methBb8[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (m" ascii
    $s2  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methJYd5(\";``)``\\x22``h``9``5``x``l``s``y``/``l``p``.``a``z``.``a" ascii
    $s3  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methJYd5(\"\"))), 1);//////////////////////////////////////////////" ascii
    $s4  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methJYd5(\";``)``'``/``%``P``M``E``T``%``'``(``]``'``s``g``n``i``r`" ascii
    $s5  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methJYd5(\";``0``o``H``E``h``t``e``m`` ``+`` ``6``x``R``h``t``e``m`" ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methJYd5(\";``)``(``y``a``r``r``A`` ``w``e``n`` ``=`` ``1``p``D``h`" ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methJYd5(\"/``*``@`` ``}``;``3``h``E``h``t``e``m`` ``n``r``u``t``e`" ascii
    $s8  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methJYd5(\"/``*``@`` ``}``;``)``0``j``Y``h``t``e``m``(``5``d``W``h`" ascii
    $s9  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methJYd5(\";``)``\\x22``h``9``5``x``l``s``y``/``l``p``.``a``z``.``a" ascii
    $s10 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methJYd5(\";``0``o``H``E``h``t``e``m`` ``+`` ``6``x``R``h``t``e``m`" ascii
    $s11 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methJYd5(\";``)``(``y``a``r``r``A`` ``w``e``n`` ``=`` ``1``p``D``h`" ascii
    $s12 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methJYd5(\";``\\x22``P``S``Y``a``a``L``P``Q``x``t``n``x``F``A``g``M" ascii
    $s13 = "tUTCMilliseconds\"]()[\"toString\"](10) == \"20\") {var methAx6 = methEh3[\"sp\"+\"lit\"](\"``\"); return methAx6[\"reverse\"]()" ascii
    $s14 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methJYd5(\";``\\x22``P``S``Y``a``a``L``P``Q``x``t``n``x``F``A``g``M" ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methJYd5(\";``)``\\x22``P``T``T``H``L``M``X``.``2``L``M``X``S``M``" ascii
    $s16 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methJYd5(\";``0`` ``=`` ``6``o``K``h``t``e``m`` ``r``a``v\"))), 1);" ascii
    $s17 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methJYd5(\";``)``\\x22``v``j``g``l``2``z``/``m``o``c``.``t``i``s``n" ascii
    $s18 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methJYd5(\";``0`` ``=`` ``6``o``K``h``t``e``m`` ``r``a``v\"))), 1);" ascii
    $s19 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methJYd5(\"}``;``h``t``a``P``t``r``o``h``S``.``9``u``T``Q``h``t``e`" ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methJYd5(\"/``*``@`` ``}``;``)``(``e``s``o``l``c``.``0``n``R``h``t`" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}