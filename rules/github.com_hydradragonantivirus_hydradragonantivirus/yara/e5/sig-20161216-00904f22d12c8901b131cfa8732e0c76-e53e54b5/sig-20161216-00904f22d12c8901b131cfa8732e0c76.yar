rule sig_20161216_00904f22d12c8901b131cfa8732e0c76 {
  meta:
    description = "datamaliciousorder - file 20161216_00904f22d12c8901b131cfa8732e0c76.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0ef1dd14cdfd24d7974cfb37553002ea3932d81b30f38ca49928dc77382a3df3"

  strings:
    $s1  = "function methWOs9(methRZu6) {eval(\"/*@cc_on var methJLc7 = new Date() @*/\");methJLc7[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if" ascii
    $s2  = "[\"getUTCMilliseconds\"]()[\"toString\"](10) == \"20\") {var methMy1 = methRZu6[\"sp\"+\"lit\"](\"``\"); return methMy1[\"revers" ascii
    $s3  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methWOs9(\";``)``'``/``%``P``M``E``T``%``'``(``]``'``s``g``n``i``r`" ascii
    $s4  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methWOs9(\";``)``\\x22``h``d``f``o``1``v``f``c``s``/``m``o``c``.``a" ascii
    $s5  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methWOs9(\";``)``\\x22``c``o``a``4``k``g``r``/``l``p``.``m``o``c``a" ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methWOs9(\"/``*``@`` ``}``;``1``y``M``h``t``e``m`` ``n``r``u``t``e`" ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methWOs9(\";``)``\\x22``h``d``f``o``1``v``f``c``s``/``m``o``c``.``a" ascii
    $s8  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methWOs9(\"/``*``@`` ``}``;``6``u``Z``R``h``t``e``m`` ``n``r``u``t`" ascii
    $s9  = "function methWOs9(methRZu6) {eval(\"/*@cc_on var methJLc7 = new Date() @*/\");methJLc7[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if" ascii
    $s10 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methWOs9(\";``\\x22``/``\\x22``+``\\x22``/``\\x22``+``\\x22``:``\\x" ascii
    $s11 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methWOs9(\";``\\x22``/``\\x22``+``\\x22``/``\\x22``+``\\x22``:``\\x" ascii
    $s12 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methWOs9(\";``)``\\x22``l``l``e``h``S``.``t``p``i``r``c``S``W``\\x2" ascii
    $s13 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methWOs9(\"/``*``@`` ``}``;``)``(``e``s``o``l``c``.``8``s``N``h``t`" ascii
    $s14 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methWOs9(\";``)``\\x22``j``4``n``e``y``l``7``s``/``h``c``.``f``a``e" ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methWOs9(\";``)``\\x22``P``T``T``H``L``M``X``.``2``L``M``X``S``M``" ascii
    $s16 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methWOs9(\"/``*``@`` ``}``;``6``u``Z``R``h``t``e``m`` ``n``r``u``t`" ascii
    $s17 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methWOs9(\";``0`` ``=`` ``1``e``X``X``h``t``e``m`` ``r``a``v\"))), " ascii
    $s18 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methWOs9(\";``5``u``K``T``h``t``e``m`` ``+`` ``5``n``M``N``h``t``e`" ascii
    $s19 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methWOs9(\"/``*``@`` ``}``;``}``;``e``u``n``i``t``n``o``c``{`` ``)`" ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methWOs9(\";``1``+``1``=``1``p``F``h``t``e``m`` ``r``a``v``;``)``" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}