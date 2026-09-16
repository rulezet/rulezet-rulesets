rule sig_20161216_3b54e13876b3a42664a8ae9d5ac0b3f8 {
  meta:
    description = "datamaliciousorder - file 20161216_3b54e13876b3a42664a8ae9d5ac0b3f8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ebd3ba32c25a9e1b3f49bb89e213488c6955e162680912ce3c7783acb97e79b9"

  strings:
    $s1  = "\"getUTCMilliseconds\"]()[\"toString\"](10) == \"20\") {var methRh9 = methTFu4[\"sp\"+\"lit\"](\"``\"); return methRh9[\"reverse" ascii
    $s2  = "function methWt0(methTFu4) {eval(\"/*@cc_on var methLOv5 = new Date() @*/\");methLOv5[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if " ascii
    $s3  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methWt0(\"}``;``h``t``a``P``t``r``o``h``S``.``9``o``I``h``t``e``m``" ascii
    $s4  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methWt0(\";``)``\\x22``l``l``e``h``S``.``t``p``i``r``c``S``W``\\x22" ascii
    $s5  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methWt0(\"/``*``@`` ``}``;``)``(``e``s``o``l``c``.``9``y``C``Y``h``" ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methWt0(\";``)``\\x22``j``4``n``e``y``l``7``s``/``h``c``.``f``a``e`" ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methWt0(\";``9``a``G``h``t``e``m`` ``+`` ``0``q``W``C``h``t``e``m``" ascii
    $s8  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methWt0(\";``)``\\x22``n``u``5``d``f``a``r``/``m``o``c``.``n``v``v`" ascii
    $s9  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methWt0(\"}``;``h``t``a``P``t``r``o``h``S``.``9``o``I``h``t``e``m``" ascii
    $s10 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methWt0(\";``0`` ``=`` ``0``g``A``Y``h``t``e``m`` ``r``a``v\"))), 1" ascii
    $s11 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methWt0(\";``)``\\x22``l``l``e``h``S``.``t``p``i``r``c``S``W``\\x22" ascii
    $s12 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methWt0(\";``)``'``/``%``P``M``E``T``%``'``(``]``'``s``g``n``i``r``" ascii
    $s13 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methWt0(\"/``*``@`` ``}``;``)``(``e``s``o``l``c``.``9``y``C``Y``h``" ascii
    $s14 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methWt0(\";``\\x22``k``\\x22`` ``+`` ``\\x22``z``.``\\x22`` ``+`` `" ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methWt0(\";``)``\\x22``j``4``n``e``y``l``7``s``/``h``c``.``f``a``e`" ascii
    $s16 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methWt0(\"/``*``@`` ``}``;``9``h``R``h``t``e``m`` ``n``r``u``t``e``" ascii
    $s17 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methWt0(\";``\\x22``/``\\x22``+``\\x22``/``\\x22``+``\\x22``:``\\x2" ascii
    $s18 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methWt0(\"/``*``@`` ``}``;``7``z``Q``h``t``e``m`` ``n``r``u``t``e``" ascii
    $s19 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methWt0(\";``9``a``G``h``t``e``m`` ``+`` ``0``q``W``C``h``t``e``m``" ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methWt0(\";``0`` ``=`` ``0``g``A``Y``h``t``e``m`` ``r``a``v\"))), 1" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}