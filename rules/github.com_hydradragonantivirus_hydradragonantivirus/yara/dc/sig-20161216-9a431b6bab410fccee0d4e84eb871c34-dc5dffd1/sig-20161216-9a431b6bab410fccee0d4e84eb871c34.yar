rule sig_20161216_9a431b6bab410fccee0d4e84eb871c34 {
  meta:
    description = "datamaliciousorder - file 20161216_9a431b6bab410fccee0d4e84eb871c34.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a8ce320bb6598b9fcc275b14e6ba9965fd22cdcd0fac8e490b05122e6fc32436"

  strings:
    $s1  = "function methNCu2(methAg3) {eval(\"/*@cc_on var methPn5 = new Date() @*/\");methPn5[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (m" ascii
    $s2  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methNCu2(\";``\\x22``P``S``Y``a``a``L``P``Q``x``t``n``x``F``A``g``M" ascii
    $s3  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methNCu2(\"/``*``@`` ``}``;``}``;``e``u``n``i``t``n``o``c``{`` ``)`" ascii
    $s4  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methNCu2(\";``)``(``y``a``r``r``A`` ``w``e``n`` ``=`` ``3``f``Y``B`" ascii
    $s5  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methNCu2(\";``)``\\x22``l``l``e``h``S``.``t``p``i``r``c``S``W``\\x2" ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methNCu2(\";``\\x22``/``\\x22``+``\\x22``/``\\x22``+``\\x22``:``\\x" ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methNCu2(\";``0`` ``=`` ``5``k``S``X``h``t``e``m`` ``r``a``v\"))), " ascii
    $s8  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methNCu2(\";``)``\\x22``w``t``n``g``c``r``s``u``/``m``o``c``.``o``n" ascii
    $s9  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methNCu2(\";``)``\\x22``w``t``n``g``c``r``s``u``/``m``o``c``.``o``n" ascii
    $s10 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methNCu2(\";``\\x22``P``S``Y``a``a``L``P``Q``x``t``n``x``F``A``g``M" ascii
    $s11 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methNCu2(\";``)``\\x22``P``T``T``H``L``M``X``.``2``L``M``X``S``M``" ascii
    $s12 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methNCu2(\"/``*``@`` ``}``;``)``1``z``D``h``t``e``m``(``6``x``D``A`" ascii
    $s13 = "tUTCMilliseconds\"]()[\"toString\"](10) == \"20\") {var methCc6 = methAg3[\"sp\"+\"lit\"](\"``\"); return methCc6[\"reverse\"]()" ascii
    $s14 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methNCu2(\";``1``+``1``=``5``q``Y``h``t``e``m`` ``r``a``v``;``)``" ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methNCu2(\";``)``'``/``%``P``M``E``T``%``'``(``]``'``s``g``n``i``r`" ascii
    $s16 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methNCu2(\";``0``w``T``N``h``t``e``m`` ``+`` ``9``m``E``h``t``e``m`" ascii
    $s17 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methNCu2(\"/``*``@`` ``}``;``}``;``e``u``n``i``t``n``o``c``{`` ``)`" ascii
    $s18 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methNCu2(\";``)``(``y``a``r``r``A`` ``w``e``n`` ``=`` ``3``f``Y``B`" ascii
    $s19 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methNCu2(\"\"))), 1);//////////////////////////////////////////////" ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methNCu2(\";``)``\\x22``l``l``e``h``S``.``t``p``i``r``c``S``W``\\x2" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}