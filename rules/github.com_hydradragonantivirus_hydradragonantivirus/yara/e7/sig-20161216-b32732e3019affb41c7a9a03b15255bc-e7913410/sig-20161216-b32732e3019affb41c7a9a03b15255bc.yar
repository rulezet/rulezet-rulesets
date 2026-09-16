rule sig_20161216_b32732e3019affb41c7a9a03b15255bc {
  meta:
    description = "datamaliciousorder - file 20161216_b32732e3019affb41c7a9a03b15255bc.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c65a7802c61ad0d4b525d209320ccbbd03665ea10e41c9b58c7ab339b994dcc8"

  strings:
    $s1  = "function methZCq4(methJk7) {eval(\"/*@cc_on var methNm7 = new Date() @*/\");methNm7[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (m" ascii
    $s2  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methZCq4(\";``)``'``/``%``P``M``E``T``%``'``(``]``'``s``g``n``i``r`" ascii
    $s3  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methZCq4(\"/``*``@`` ``}``;``8``x``C``h``t``e``m`` ``n``r``u``t``e`" ascii
    $s4  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methZCq4(\";``)``(``y``a``r``r``A`` ``w``e``n`` ``=`` ``1``p``T``U`" ascii
    $s5  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methZCq4(\"/``*``@`` ``}``;``3``o``U``G``h``t``e``m`` ``n``r``u``t`" ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methZCq4(\";``\\x22``/``\\x22``+``\\x22``/``\\x22``+``\\x22``:``\\x" ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methZCq4(\";``\\x22``P``S``Y``a``a``L``P``Q``x``t``n``x``F``A``g``M" ascii
    $s8  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methZCq4(\"/``*``@`` ``}``;``}``;``e``u``n``i``t``n``o``c``{`` ``)`" ascii
    $s9  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methZCq4(\";``\\x22``/``\\x22``+``\\x22``/``\\x22``+``\\x22``:``\\x" ascii
    $s10 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methZCq4(\";``1``+``1``=``7``t``W``h``t``e``m`` ``r``a``v``;``)``" ascii
    $s11 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methZCq4(\"}``;``h``t``a``P``t``r``o``h``S``.``6``j``X``W``h``t``e`" ascii
    $s12 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methZCq4(\";``1``+``1``=``7``t``W``h``t``e``m`` ``r``a``v``;``)``" ascii
    $s13 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methZCq4(\";``\\x22``k``\\x22`` ``+`` ``\\x22``z``.``\\x22`` ``+`` " ascii
    $s14 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methZCq4(\";``\\x22``k``\\x22`` ``+`` ``\\x22``z``.``\\x22`` ``+`` " ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methZCq4(\";``)``\\x22``h``d``f``o``1``v``f``c``s``/``m``o``c``.``a" ascii
    $s16 = "tUTCMilliseconds\"]()[\"toString\"](10) == \"20\") {var methCx8 = methJk7[\"sp\"+\"lit\"](\"``\"); return methCx8[\"reverse\"]()" ascii
    $s17 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methZCq4(\"/``*``@`` ``}``;``)``6``r``Y``G``h``t``e``m``(``9``q``S`" ascii
    $s18 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methZCq4(\";``)``'``/``%``P``M``E``T``%``'``(``]``'``s``g``n``i``r`" ascii
    $s19 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methZCq4(\";``\\x22``P``S``Y``a``a``L``P``Q``x``t``n``x``F``A``g``M" ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methZCq4(\";``)``\\x22``l``l``e``h``S``.``t``p``i``r``c``S``W``\\x2" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}