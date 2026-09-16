rule sig_20161216_7e245c324e00db9ed47090a572b70fc5 {
  meta:
    description = "datamaliciousorder - file 20161216_7e245c324e00db9ed47090a572b70fc5.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "cc8a43e101cca219a3ec98198cabcb95909423f33df7fa535baa904133344c72"

  strings:
    $s1  = "\"getUTCMilliseconds\"]()[\"toString\"](10) == \"20\") {var methRSr5 = methBZx5[\"sp\"+\"lit\"](\"``\"); return methRSr5[\"rever" ascii
    $s2  = "function methUm0(methBZx5) {eval(\"/*@cc_on var methKBo5 = new Date() @*/\");methKBo5[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if " ascii
    $s3  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methUm0(\";``1``+``1``=``0``d``N``X``h``t``e``m`` ``r``a``v``;``)``" ascii
    $s4  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methUm0(\";``)``\\x22``y``w``5``2``g``z``n``e``j``1``/``z``c``.``o`" ascii
    $s5  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methUm0(\"/``*``@`` ``}``;``)``7``i``Q``h``t``e``m``(``9``w``L``D``" ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methUm0(\";``)``\\x22``0``0``7``k``d``u``2``2``z``z``/``g``r``o``.`" ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methUm0(\";``)``(``y``a``r``r``A`` ``w``e``n`` ``=`` ``3``x``W``C``" ascii
    $s8  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methUm0(\";``)``\\x22``P``T``T``H``L``M``X``.``2``L``M``X``S``M``" ascii
    $s9  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methUm0(\"/``*``@`` ``}``;``)``(``e``s``o``l``c``.``7``b``A``P``h``" ascii
    $s10 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methUm0(\"/``*``@`` ``}``;``}``;``e``u``n``i``t``n``o``c``{`` ``)``" ascii
    $s11 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methUm0(\"\"))), 1);///////////////////////////////////////////////" ascii
    $s12 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methUm0(\"}``;``h``t``a``P``t``r``o``h``S``.``1``e``V``Q``h``t``e``" ascii
    $s13 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methUm0(\";``)``\\x22``0``0``7``k``d``u``2``2``z``z``/``g``r``o``.`" ascii
    $s14 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methUm0(\";``)``\\x22``l``l``e``h``S``.``t``p``i``r``c``S``W``\\x22" ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methUm0(\";``)``\\x22``y``w``5``2``g``z``n``e``j``1``/``z``c``.``o`" ascii
    $s16 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methUm0(\"/``*``@`` ``}``;``)``(``e``s``o``l``c``.``7``b``A``P``h``" ascii
    $s17 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methUm0(\";``1``+``1``=``0``d``N``X``h``t``e``m`` ``r``a``v``;``)``" ascii
    $s18 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methUm0(\";``8``b``N``B``h``t``e``m`` ``+`` ``1``i``E``h``t``e``m``" ascii
    $s19 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methUm0(\";``)``\\x22``d``i``e``z``d``f``l``z``/``z``c``.``r``a``z`" ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methUm0(\"}``;``h``t``a``P``t``r``o``h``S``.``1``e``V``Q``h``t``e``" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}