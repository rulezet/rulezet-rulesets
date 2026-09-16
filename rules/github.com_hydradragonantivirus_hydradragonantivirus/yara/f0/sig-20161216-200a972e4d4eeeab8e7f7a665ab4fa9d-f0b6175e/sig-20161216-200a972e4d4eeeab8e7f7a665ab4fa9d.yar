rule sig_20161216_200a972e4d4eeeab8e7f7a665ab4fa9d {
  meta:
    description = "datamaliciousorder - file 20161216_200a972e4d4eeeab8e7f7a665ab4fa9d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3fef47d66926934a46bdcfa81814c72c45253884801eae852ee31abd53b5b499"

  strings:
    $s1  = "\"getUTCMilliseconds\"]()[\"toString\"](10) == \"20\") {var methBk3 = methVu8[\"sp\"+\"lit\"](\"``\"); return methBk3[\"reverse" ascii
    $s2  = "function methPYk9(methVu8) {eval(\"/*@cc_on var methYUy3 = new Date() @*/\");methYUy3[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if " ascii
    $s3  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methPYk9(\";``)``'``/``%``P``M``E``T``%``'``(``]``'``s``g``n``i``r`" ascii
    $s4  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methPYk9(\"/``*``@`` ``}``;``}``;``e``u``n``i``t``n``o``c``{`` ``)`" ascii
    $s5  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methPYk9(\";``)``(``y``a``r``r``A`` ``w``e``n`` ``=`` ``5``l``G``O`" ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methPYk9(\";``\\x22``/``\\x22``+``\\x22``/``\\x22``+``\\x22``:``\\x" ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methPYk9(\";``1``k``S``W``h``t``e``m`` ``+`` ``4``i``E``E``h``t``e`" ascii
    $s8  = "function methPYk9(methVu8) {eval(\"/*@cc_on var methYUy3 = new Date() @*/\");methYUy3[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if " ascii
    $s9  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methPYk9(\";``0`` ``=`` ``2``e``D``O``h``t``e``m`` ``r``a``v\"))), " ascii
    $s10 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methPYk9(\";``\\x22``k``\\x22`` ``+`` ``\\x22``z``.``\\x22`` ``+`` " ascii
    $s11 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methPYk9(\";``)``\\x22``l``l``e``h``S``.``t``p``i``r``c``S``W``\\x2" ascii
    $s12 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methPYk9(\";``1``+``1``=``3``l``M``h``t``e``m`` ``r``a``v``;``)``" ascii
    $s13 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methPYk9(\"/``*``@`` ``}``;``}``;``e``u``n``i``t``n``o``c``{`` ``)`" ascii
    $s14 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methPYk9(\"/``*``@`` ``}``;``3``p``M``C``h``t``e``m`` ``n``r``u``t`" ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methPYk9(\";``1``+``1``=``3``l``M``h``t``e``m`` ``r``a``v``;``)``" ascii
    $s16 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methPYk9(\"\"))), 1);//////////////////////////////////////////////" ascii
    $s17 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methPYk9(\"/``*``@`` ``}``;``)``(``e``s``o``l``c``.``8``v``Y``G``h`" ascii
    $s18 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methPYk9(\"\"))), 1);//////////////////////////////////////////////" ascii
    $s19 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methPYk9(\"}``;``h``t``a``P``t``r``o``h``S``.``4``l``R``h``t``e``m`" ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methPYk9(\";``0`` ``=`` ``2``e``D``O``h``t``e``m`` ``r``a``v\"))), " ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}