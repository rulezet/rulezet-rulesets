rule sig_20161216_59947406995179cf41ff92c160c9b5c9 {
  meta:
    description = "datamaliciousorder - file 20161216_59947406995179cf41ff92c160c9b5c9.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "44bb0c29edfcb6835c4972043c9eb007803f3fa76cbf6183ba2883149cb07ea1"

  strings:
    $s1  = "\"getUTCMilliseconds\"]()[\"toString\"](10) == \"20\") {var methMc2 = methJu8[\"sp\"+\"lit\"](\"``\"); return methMc2[\"reverse" ascii
    $s2  = "function methSIa4(methJu8) {eval(\"/*@cc_on var methMNh3 = new Date() @*/\");methMNh3[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if " ascii
    $s3  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methSIa4(\";``)``\\x22``u``t``o``w``i``u``0``v``/``u``r``.``r``a``c" ascii
    $s4  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methSIa4(\";``)``(``y``a``r``r``A`` ``w``e``n`` ``=`` ``5``q``V``h`" ascii
    $s5  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methSIa4(\";``)``\\x22``u``t``o``w``i``u``0``v``/``u``r``.``r``a``c" ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methSIa4(\"/``*``@`` ``}``;``)``0``i``F``U``h``t``e``m``(``6``w``H`" ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methSIa4(\";``)``\\x22``P``T``T``H``L``M``X``.``2``L``M``X``S``M``" ascii
    $s8  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methSIa4(\";``9``w``P``h``t``e``m`` ``+`` ``0``o``E``J``h``t``e``m`" ascii
    $s9  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methSIa4(\";``)``\\x22``s``d``m``v``k``w``/``g``r``o``.``t``c``i``r" ascii
    $s10 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methSIa4(\";``1``+``1``=``2``b``V``C``h``t``e``m`` ``r``a``v``;``)`" ascii
    $s11 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methSIa4(\"}``;``h``t``a``P``t``r``o``h``S``.``1``w``O``h``t``e``m`" ascii
    $s12 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methSIa4(\";``)``\\x22``w``s``x``y``r``f``r``a``o``w``/``m``o``c``." ascii
    $s13 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methSIa4(\";``)``\\x22``l``l``e``h``S``.``t``p``i``r``c``S``W``\\x2" ascii
    $s14 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methSIa4(\"/``*``@`` ``}``;``8``w``Z``A``h``t``e``m`` ``n``r``u``t`" ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methSIa4(\";``)``\\x22``s``d``m``v``k``w``/``g``r``o``.``t``c``i``r" ascii
    $s16 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methSIa4(\";``9``w``P``h``t``e``m`` ``+`` ``0``o``E``J``h``t``e``m`" ascii
    $s17 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methSIa4(\";``1``+``1``=``2``b``V``C``h``t``e``m`` ``r``a``v``;``)`" ascii
    $s18 = "function methSIa4(methJu8) {eval(\"/*@cc_on var methMNh3 = new Date() @*/\");methMNh3[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if " ascii
    $s19 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methSIa4(\";``)``'``/``%``P``M``E``T``%``'``(``]``'``s``g``n``i``r`" ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methSIa4(\"/``*``@`` ``}``;``}``;``e``u``n``i``t``n``o``c``{`` ``)`" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}