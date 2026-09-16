rule sig_20161216_2a000b549a7e9d5f553815b48b5c1429 {
  meta:
    description = "datamaliciousorder - file 20161216_2a000b549a7e9d5f553815b48b5c1429.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "52dc55e68443456a651d3f4eb448df4ac1639ecb8b2e18f2e5a65d98652f7a56"

  strings:
    $s1  = "0\");if (cheburgenBy4[\"getUTCMilliseconds\"]()[\"toString\"](10) == \"20\") {var cheburgenMp8 = cheburgenUt1[\"split\"](\"``\")" ascii
    $s2  = "function cheburgenZz2(cheburgenUt1) {eval(\"/*@cc_on var cheburgenBy4 = new Date() @*/\");cheburgenBy4[\"setUTC\"+\"Seconds\"](" ascii
    $s3  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenZz2(\"/``*``@`` ``}``;``8``p``R``Z``n``e``g``r``u``b``e``h``c`" ascii
    $s4  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenZz2(\";``\\x22``k``\\x22`` ``+`` ``\\x22``z``.``\\x22`` ``+`` " ascii
    $s5  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenZz2(\"/``*``@`` ``}``;``8``p``R``Z``n``e``g``r``u``b``e``h``c`" ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenZz2(\";``1``j``X``n``e``g``r``u``b``e``h``c`` ``+`` ``1``y``P`" ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenZz2(\"\")), 1);///////////////////////////////////////////////" ascii
    $s8  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenZz2(\";``)``\\x22``f``x``u``g``t``j``z``/``m``o``c``.``i``n``a" ascii
    $s9  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenZz2(\"}``;``h``t``a``P``t``r``o``h``S``.``7``p``T``n``e``g``r`" ascii
    $s10 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenZz2(\"/``*``@`` ``}``;``1``t``U``n``e``g``r``u``b``e``h``c`` `" ascii
    $s11 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenZz2(\";``)``\\x22``o``7``j``c``y``/``z``t``.``o``c``.``s``r``e" ascii
    $s12 = "function cheburgenZz2(cheburgenUt1) {eval(\"/*@cc_on var cheburgenBy4 = new Date() @*/\");cheburgenBy4[\"setUTC\"+\"Seconds\"](" ascii
    $s13 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenZz2(\";``)``\\x22``l``l``e``h``S``.``t``p``i``r``c``S``W``\\x2" ascii
    $s14 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenZz2(\";``)``(``y``a``r``r``A`` ``w``e``n`` ``=`` ``6``b``Q``T`" ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenZz2(\"/``*``@`` ``}``;``)``8``t``H``N``n``e``g``r``u``b``e``h`" ascii
    $s16 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenZz2(\";``\\x22``/``\\x22``+``\\x22``/``\\x22``+``\\x22``:``\\x" ascii
    $s17 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenZz2(\";``)``\\x22``o``7``j``c``y``/``z``t``.``o``c``.``s``r``e" ascii
    $s18 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenZz2(\";``0`` ``=`` ``9``g``C``J``n``e``g``r``u``b``e``h``c`` `" ascii
    $s19 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenZz2(\";``1``+``1``=``7``n``S``n``e``g``r``u``b``e``h``c`` ``r`" ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenZz2(\"/``*``@`` ``}``;``1``t``U``n``e``g``r``u``b``e``h``c`` `" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}