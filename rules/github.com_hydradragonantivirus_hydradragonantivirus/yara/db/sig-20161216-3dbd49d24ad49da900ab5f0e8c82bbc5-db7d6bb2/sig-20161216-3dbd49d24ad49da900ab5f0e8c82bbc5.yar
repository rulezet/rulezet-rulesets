rule sig_20161216_3dbd49d24ad49da900ab5f0e8c82bbc5 {
  meta:
    description = "datamaliciousorder - file 20161216_3dbd49d24ad49da900ab5f0e8c82bbc5.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6a205878a138d351aa838f4a8d1a6ccea3606542b5982abd3cc032e6e2334dff"

  strings:
    $s1  = "getUTCMilliseconds\"]()[\"toString\"](10) == \"20\") {var methAPe8 = methYj9[\"sp\"+\"lit\"](\"``\"); return methAPe8[\"reverse" ascii
    $s2  = "function methOo8(methYj9) {eval(\"/*@cc_on var methMXc8 = new Date() @*/\");methMXc8[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (" ascii
    $s3  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methOo8(\";``)``\\x22``r``3``b``n``f``g``/``m``o``c``.``h``s``i``l`" ascii
    $s4  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methOo8(\";``0`` ``=`` ``1``x``E``D``h``t``e``m`` ``r``a``v\"))), 1" ascii
    $s5  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methOo8(\"/``*``@`` ``}``;``8``e``P``A``h``t``e``m`` ``n``r``u``t``" ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methOo8(\";``)``\\x22``m``h``4``5``m``c``1``2``/``m``o``c``.``a``i`" ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methOo8(\";``\\x22``k``\\x22`` ``+`` ``\\x22``z``.``\\x22`` ``+`` `" ascii
    $s8  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methOo8(\"/``*``@`` ``}``;``)``(``e``s``o``l``c``.``9``r``A``h``t``" ascii
    $s9  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methOo8(\";``)``(``y``a``r``r``A`` ``w``e``n`` ``=`` ``8``p``Z``h``" ascii
    $s10 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methOo8(\";``)``\\x22``m``h``4``5``m``c``1``2``/``m``o``c``.``a``i`" ascii
    $s11 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methOo8(\"}``;``h``t``a``P``t``r``o``h``S``.``2``p``T``T``h``t``e``" ascii
    $s12 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methOo8(\";``\\x22``/``\\x22``+``\\x22``/``\\x22``+``\\x22``:``\\x2" ascii
    $s13 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methOo8(\";``\\x22``k``\\x22`` ``+`` ``\\x22``z``.``\\x22`` ``+`` `" ascii
    $s14 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methOo8(\"/``*``@`` ``}``;``)``2``a``Z``h``t``e``m``(``5``z``N``B``" ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methOo8(\"/``*``@`` ``}``;``8``e``P``A``h``t``e``m`` ``n``r``u``t``" ascii
    $s16 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methOo8(\";``)``\\x22``l``l``e``h``S``.``t``p``i``r``c``S``W``\\x22" ascii
    $s17 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methOo8(\"/``*``@`` ``}``;``9``j``Y``h``t``e``m`` ``n``r``u``t``e``" ascii
    $s18 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methOo8(\";``)``\\x22``q``g``p``l``c``i``d``g``/``r``i``.``i``h``g`" ascii
    $s19 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methOo8(\";``)``\\x22``r``3``b``n``f``g``/``m``o``c``.``h``s``i``l`" ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methOo8(\"\"))), 1);///////////////////////////////////////////////" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}