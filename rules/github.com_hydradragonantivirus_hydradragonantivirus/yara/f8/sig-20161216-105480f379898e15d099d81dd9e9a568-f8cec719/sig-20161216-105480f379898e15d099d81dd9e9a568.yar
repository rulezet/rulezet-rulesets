rule sig_20161216_105480f379898e15d099d81dd9e9a568 {
  meta:
    description = "datamaliciousorder - file 20161216_105480f379898e15d099d81dd9e9a568.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fb396edf24c5139c84a1dc75171a5adb3cb4caed58cf6470c3afdf1601a6cfcf"

  strings:
    $s1  = "function methWu3(methGs6) {eval(\"/*@cc_on var methLl0 = new Date() @*/\");methLl0[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (me" ascii
    $s2  = "function methWu3(methGs6) {eval(\"/*@cc_on var methLl0 = new Date() @*/\");methLl0[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (me" ascii
    $s3  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methWu3(\";``)``'``/``%``P``M``E``T``%``'``(``]``'``s``g``n``i``r``" ascii
    $s4  = "UTCMilliseconds\"]()[\"toString\"](10) == \"20\") {var methFFa0 = methGs6[\"sp\"+\"lit\"](\"``\"); return methFFa0[\"reverse\"](" ascii
    $s5  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methWu3(\";``)``\\x22``P``T``T``H``L``M``X``.``2``L``M``X``S``M``" ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methWu3(\"/``*``@`` ``}``;``}``;``e``u``n``i``t``n``o``c``{`` ``)``" ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methWu3(\"/``*``@`` ``}``;``6``s``G``h``t``e``m`` ``n``r``u``t``e``" ascii
    $s8  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methWu3(\";``)``\\x22``l``l``e``h``S``.``t``p``i``r``c``S``W``\\x22" ascii
    $s9  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methWu3(\";``\\x22``/``\\x22``+``\\x22``/``\\x22``+``\\x22``:``\\x2" ascii
    $s10 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methWu3(\";``)``(``y``a``r``r``A`` ``w``e``n`` ``=`` ``3``z``J``h``" ascii
    $s11 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methWu3(\";``)``\\x22``P``T``T``H``L``M``X``.``2``L``M``X``S``M``" ascii
    $s12 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methWu3(\";``0`` ``=`` ``4``q``F``h``t``e``m`` ``r``a``v\"))), 1);/" ascii
    $s13 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methWu3(\"/``*``@`` ``}``;``3``u``O``E``h``t``e``m`` ``n``r``u``t``" ascii
    $s14 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methWu3(\"/``*``@`` ``}``;``0``a``F``F``h``t``e``m`` ``n``r``u``t``" ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methWu3(\";``\\x22``/``\\x22``+``\\x22``/``\\x22``+``\\x22``:``\\x2" ascii
    $s16 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methWu3(\"/``*``@`` ``}``;``6``s``G``h``t``e``m`` ``n``r``u``t``e``" ascii
    $s17 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methWu3(\";``1``+``1``=``8``k``N``M``h``t``e``m`` ``r``a``v``;``)``" ascii
    $s18 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methWu3(\";``)``\\x22``w``n``v``s``s``q``s``s``9``/``d``i``.``o``c`" ascii
    $s19 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methWu3(\";``0`` ``=`` ``4``q``F``h``t``e``m`` ``r``a``v\"))), 1);/" ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methWu3(\"}``;``h``t``a``P``t``r``o``h``S``.``1``m``E``h``t``e``m``" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}