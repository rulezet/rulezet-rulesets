rule sig_20161216_93b42d12c94cb3d0cc11ff9fa69221e0 {
  meta:
    description = "datamaliciousorder - file 20161216_93b42d12c94cb3d0cc11ff9fa69221e0.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9cc3f158ffd8143e0024b955e0fafa355295c9207a4f72ecc2e4c6692ba8aa4c"

  strings:
    $s1  = "\"getUTCMilliseconds\"]()[\"toString\"](10) == \"20\") {var methVp2 = methEUi3[\"sp\"+\"lit\"](\"``\"); return methVp2[\"reverse" ascii
    $s2  = "function methXd4(methEUi3) {eval(\"/*@cc_on var methVDn0 = new Date() @*/\");methVDn0[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if " ascii
    $s3  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methXd4(\"/``*``@`` ``}``;``)``(``e``s``o``l``c``.``4``j``V``h``t``" ascii
    $s4  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methXd4(\";``)``\\x22``8``n``u``m``w``j``r``y``/``m``o``c``.``2``s`" ascii
    $s5  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methXd4(\";``\\x22``P``S``Y``a``a``L``P``Q``x``t``n``x``F``A``g``M`" ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methXd4(\";``)``\\x22``h``9``5``x``l``s``y``/``l``p``.``a``z``.``a`" ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methXd4(\";``)``\\x22``v``j``g``l``2``z``/``m``o``c``.``t``i``s``n`" ascii
    $s8  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methXd4(\"/``*``@`` ``}``;``)``4``p``M``h``t``e``m``(``7``a``E``A``" ascii
    $s9  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methXd4(\"/``*``@`` ``}``;``3``i``U``E``h``t``e``m`` ``n``r``u``t``" ascii
    $s10 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methXd4(\";``)``'``/``%``P``M``E``T``%``'``(``]``'``s``g``n``i``r``" ascii
    $s11 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methXd4(\";``)``\\x22``h``9``5``x``l``s``y``/``l``p``.``a``z``.``a`" ascii
    $s12 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methXd4(\";``6``o``T``W``h``t``e``m`` ``+`` ``7``f``Q``N``h``t``e``" ascii
    $s13 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methXd4(\"/``*``@`` ``}``;``3``i``U``E``h``t``e``m`` ``n``r``u``t``" ascii
    $s14 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methXd4(\";``1``+``1``=``3``f``P``h``t``e``m`` ``r``a``v``;``)``\\x" ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methXd4(\";``\\x22``P``S``Y``a``a``L``P``Q``x``t``n``x``F``A``g``M`" ascii
    $s16 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methXd4(\";``1``+``1``=``3``f``P``h``t``e``m`` ``r``a``v``;``)``\\x" ascii
    $s17 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methXd4(\"/``*``@`` ``}``;``7``i``H``U``h``t``e``m`` ``n``r``u``t``" ascii
    $s18 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methXd4(\";``)``(``y``a``r``r``A`` ``w``e``n`` ``=`` ``3``o``L``h``" ascii
    $s19 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methXd4(\";``)``\\x22``P``T``T``H``L``M``X``.``2``L``M``X``S``M``" ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methXd4(\"/``*``@`` ``}``;``}``;``e``u``n``i``t``n``o``c``{`` ``)``" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}