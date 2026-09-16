rule sig_20161216_8da4dc6ca8d52c76a4753033074f7808 {
  meta:
    description = "datamaliciousorder - file 20161216_8da4dc6ca8d52c76a4753033074f7808.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "aef7aac2a561d0e20fae22a5ec3738b93100a2749b5c92f7ba8ed6d1b9a6fe68"

  strings:
    $s1  = "function methBp9(methZDj2) {eval(\"/*@cc_on var methIBa1 = new Date() @*/\");methIBa1[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if " ascii
    $s2  = "\"getUTCMilliseconds\"]()[\"toString\"](10) == \"20\") {var methUs1 = methZDj2[\"sp\"+\"lit\"](\"``\"); return methUs1[\"reverse" ascii
    $s3  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methBp9(\"/``*``@`` ``}``;``)``(``e``s``o``l``c``.``2``q``M``T``h``" ascii
    $s4  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methBp9(\";``\\x22``/``\\x22``+``\\x22``/``\\x22``+``\\x22``:``\\x2" ascii
    $s5  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methBp9(\";``\\x22``k``\\x22`` ``+`` ``\\x22``z``.``\\x22`` ``+`` `" ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methBp9(\";``0`` ``=`` ``9``q``F``T``h``t``e``m`` ``r``a``v\"))), 1" ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methBp9(\"/``*``@`` ``}``;``9``e``V``M``h``t``e``m`` ``n``r``u``t``" ascii
    $s8  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methBp9(\";``)``\\x22``j``4``n``e``y``l``7``s``/``h``c``.``f``a``e`" ascii
    $s9  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methBp9(\";``1``u``A``V``h``t``e``m`` ``+`` ``3``j``B``Q``h``t``e``" ascii
    $s10 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methBp9(\"/``*``@`` ``}``;``)``1``k``P``V``h``t``e``m``(``2``x``J``" ascii
    $s11 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methBp9(\";``)``\\x22``l``l``e``h``S``.``t``p``i``r``c``S``W``\\x22" ascii
    $s12 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methBp9(\";``)``(``y``a``r``r``A`` ``w``e``n`` ``=`` ``4``y``U``h``" ascii
    $s13 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methBp9(\"/``*``@`` ``}``;``1``s``U``h``t``e``m`` ``n``r``u``t``e``" ascii
    $s14 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methBp9(\";``\\x22``/``\\x22``+``\\x22``/``\\x22``+``\\x22``:``\\x2" ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methBp9(\"/``*``@`` ``}``;``}``;``e``u``n``i``t``n``o``c``{`` ``)``" ascii
    $s16 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methBp9(\";``)``'``/``%``P``M``E``T``%``'``(``]``'``s``g``n``i``r``" ascii
    $s17 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methBp9(\"/``*``@`` ``}``;``9``e``V``M``h``t``e``m`` ``n``r``u``t``" ascii
    $s18 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methBp9(\"/``*``@`` ``}``;``2``j``D``Z``h``t``e``m`` ``n``r``u``t``" ascii
    $s19 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methBp9(\"\"))), 1);///////////////////////////////////////////////" ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methBp9(\";``)``(``y``a``r``r``A`` ``w``e``n`` ``=`` ``4``y``U``h``" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}