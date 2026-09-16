rule sig_20161216_177e4fab9989ee7ec15a9aaf63088e8f {
  meta:
    description = "datamaliciousorder - file 20161216_177e4fab9989ee7ec15a9aaf63088e8f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "250caa7a16dd0412a4a5e5588853866742bbbcc12bbe25ef73ab54b2409f07e5"

  strings:
    $s1  = "function methNa2(methWk3) {eval(\"/*@cc_on var methEu8 = new Date() @*/\");methEu8[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (me" ascii
    $s2  = "function methNa2(methWk3) {eval(\"/*@cc_on var methEu8 = new Date() @*/\");methEu8[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (me" ascii
    $s3  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methNa2(\"/``*``@`` ``}``;``)``(``e``s``o``l``c``.``0``w``D``h``t``" ascii
    $s4  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methNa2(\";``)``\\x22``l``l``e``h``S``.``t``p``i``r``c``S``W``\\x22" ascii
    $s5  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methNa2(\";``)``(``y``a``r``r``A`` ``w``e``n`` ``=`` ``1``l``Z``V``" ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methNa2(\";``)``\\x22``4``z``p``i``r``a``z``/``m``o``c``.``a``d``i`" ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methNa2(\";``0`` ``=`` ``1``c``L``P``h``t``e``m`` ``r``a``v\"))), 1" ascii
    $s8  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methNa2(\"/``*``@`` ``}``;``8``b``O``h``t``e``m`` ``n``r``u``t``e``" ascii
    $s9  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methNa2(\";``)``\\x22``P``T``T``H``L``M``X``.``2``L``M``X``S``M``" ascii
    $s10 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methNa2(\";``1``+``1``=``8``j``Q``h``t``e``m`` ``r``a``v``;``)``\\x" ascii
    $s11 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methNa2(\"/``*``@`` ``}``;``}``;``e``u``n``i``t``n``o``c``{`` ``)``" ascii
    $s12 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methNa2(\";``0`` ``=`` ``1``c``L``P``h``t``e``m`` ``r``a``v\"))), 1" ascii
    $s13 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methNa2(\"}``;``h``t``a``P``t``r``o``h``S``.``7``j``L``E``h``t``e``" ascii
    $s14 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methNa2(\"/``*``@`` ``}``;``8``b``O``h``t``e``m`` ``n``r``u``t``e``" ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methNa2(\";``\\x22``P``S``Y``a``a``L``P``Q``x``t``n``x``F``A``g``M`" ascii
    $s16 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methNa2(\";``)``\\x22``p``i``d``1``e``1``/``e``d``.``r``e``d``n``i`" ascii
    $s17 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methNa2(\";``\\x22``/``\\x22``+``\\x22``/``\\x22``+``\\x22``:``\\x2" ascii
    $s18 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methNa2(\";``)``\\x22``p``i``d``1``e``1``/``e``d``.``r``e``d``n``i`" ascii
    $s19 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methNa2(\"/``*``@`` ``}``;``)``(``e``s``o``l``c``.``0``w``D``h``t``" ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methNa2(\"/``*``@`` ``}``;``}``;``e``u``n``i``t``n``o``c``{`` ``)``" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}