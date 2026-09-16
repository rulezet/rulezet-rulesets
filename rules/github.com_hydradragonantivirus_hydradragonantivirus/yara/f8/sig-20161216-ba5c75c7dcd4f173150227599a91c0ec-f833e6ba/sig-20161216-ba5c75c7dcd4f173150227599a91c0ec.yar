rule sig_20161216_ba5c75c7dcd4f173150227599a91c0ec {
  meta:
    description = "datamaliciousorder - file 20161216_ba5c75c7dcd4f173150227599a91c0ec.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e079180aabd8566f898de2f023add8fab5943745f4f96640d4d0152dfeb48a09"

  strings:
    $s1  = "function methBBz1(methUDx5) {eval(\"/*@cc_on var methULl1 = new Date() @*/\");methULl1[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if" ascii
    $s2  = "[\"getUTCMilliseconds\"]()[\"toString\"](10) == \"20\") {var methTJl0 = methUDx5[\"sp\"+\"lit\"](\"``\"); return methTJl0[\"reve" ascii
    $s3  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methBBz1(\"/``*``@`` ``}``;``0``l``J``T``h``t``e``m`` ``n``r``u``t`" ascii
    $s4  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methBBz1(\";``)``\\x22``l``l``e``h``S``.``t``p``i``r``c``S``W``\\x2" ascii
    $s5  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methBBz1(\";``)``(``y``a``r``r``A`` ``w``e``n`` ``=`` ``8``g``A``G`" ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methBBz1(\";``0`` ``=`` ``2``d``B``W``h``t``e``m`` ``r``a``v\"))), " ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methBBz1(\";``3``p``V``O``h``t``e``m`` ``+`` ``5``i``N``h``t``e``m`" ascii
    $s8  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methBBz1(\";``)``'``/``%``P``M``E``T``%``'``(``]``'``s``g``n``i``r`" ascii
    $s9  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methBBz1(\"/``*``@`` ``}``;``0``l``J``T``h``t``e``m`` ``n``r``u``t`" ascii
    $s10 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methBBz1(\";``)``\\x22``j``4``n``e``y``l``7``s``/``h``c``.``f``a``e" ascii
    $s11 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methBBz1(\"/``*``@`` ``}``;``)``3``w``R``L``h``t``e``m``(``7``e``P`" ascii
    $s12 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methBBz1(\";``)``\\x22``s``w``y``v``g``u``2``n``s``/``r``a``.``m``o" ascii
    $s13 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methBBz1(\"/``*``@`` ``}``;``0``u``Y``M``h``t``e``m`` ``n``r``u``t`" ascii
    $s14 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methBBz1(\";``3``p``V``O``h``t``e``m`` ``+`` ``5``i``N``h``t``e``m`" ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methBBz1(\";``)``\\x22``h``d``f``o``1``v``f``c``s``/``m``o``c``.``a" ascii
    $s16 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methBBz1(\";``)``\\x22``s``w``y``v``g``u``2``n``s``/``r``a``.``m``o" ascii
    $s17 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methBBz1(\"/``*``@`` ``}``;``0``u``Y``M``h``t``e``m`` ``n``r``u``t`" ascii
    $s18 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methBBz1(\";``)``\\x22``w``t``n``g``c``r``s``u``/``m``o``c``.``o``n" ascii
    $s19 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methBBz1(\"/``*``@`` ``}``;``}``;``e``u``n``i``t``n``o``c``{`` ``)`" ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methBBz1(\"}``;``h``t``a``P``t``r``o``h``S``.``6``c``P``A``h``t``e`" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}