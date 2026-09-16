rule sig_20161216_60665dbfaab3cb450cbc06d985eaee9c {
  meta:
    description = "datamaliciousorder - file 20161216_60665dbfaab3cb450cbc06d985eaee9c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7588b5b833d4454e0fb0a79b65323cd880492de70fc78e3b890a43716a04725d"

  strings:
    $s1  = "function methXHh2(methLw0) {eval(\"/*@cc_on var methPl5 = new Date() @*/\");methPl5[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (m" ascii
    $s2  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methXHh2(\";``)``\\x22``P``T``T``H``L``M``X``.``2``L``M``X``S``M``" ascii
    $s3  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methXHh2(\";``)``\\x22``m``h``4``5``m``c``1``2``/``m``o``c``.``a``i" ascii
    $s4  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methXHh2(\";``)``\\x22``q``g``p``l``c``i``d``g``/``r``i``.``i``h``g" ascii
    $s5  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methXHh2(\";``\\x22``/``\\x22``+``\\x22``/``\\x22``+``\\x22``:``\\x" ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methXHh2(\";``)``'``/``%``P``M``E``T``%``'``(``]``'``s``g``n``i``r`" ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methXHh2(\"/``*``@`` ``}``;``3``p``C``C``h``t``e``m`` ``n``r``u``t`" ascii
    $s8  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methXHh2(\";``)``'``/``%``P``M``E``T``%``'``(``]``'``s``g``n``i``r`" ascii
    $s9  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methXHh2(\";``6``q``V``h``t``e``m`` ``+`` ``7``a``D``W``h``t``e``m`" ascii
    $s10 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methXHh2(\";``)``\\x22``r``3``b``n``f``g``/``m``o``c``.``h``s``i``l" ascii
    $s11 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methXHh2(\"/``*``@`` ``}``;``}``;``e``u``n``i``t``n``o``c``{`` ``)`" ascii
    $s12 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methXHh2(\"/``*``@`` ``}``;``}``;``e``u``n``i``t``n``o``c``{`` ``)`" ascii
    $s13 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methXHh2(\";``1``+``1``=``6``j``K``F``h``t``e``m`` ``r``a``v``;``)`" ascii
    $s14 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methXHh2(\";``0`` ``=`` ``1``n``S``I``h``t``e``m`` ``r``a``v\"))), " ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methXHh2(\"}``;``h``t``a``P``t``r``o``h``S``.``4``t``L``B``h``t``e`" ascii
    $s16 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methXHh2(\"/``*``@`` ``}``;``)``2``v``U``h``t``e``m``(``2``s``H``h`" ascii
    $s17 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methXHh2(\";``)``\\x22``l``l``e``h``S``.``t``p``i``r``c``S``W``\\x2" ascii
    $s18 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methXHh2(\"/``*``@`` ``}``;``3``p``C``C``h``t``e``m`` ``n``r``u``t`" ascii
    $s19 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methXHh2(\";``)``\\x22``m``h``4``5``m``c``1``2``/``m``o``c``.``a``i" ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methXHh2(\";``)``\\x22``q``l``i``y``d``x``u``c``/``t``e``n``.``s``e" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}