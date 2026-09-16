rule sig_20161216_4bfd4cda4cb2dbd0a1fd8996965fee38 {
  meta:
    description = "datamaliciousorder - file 20161216_4bfd4cda4cb2dbd0a1fd8996965fee38.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "42d98a28bfbc95b7603229d10cea0e0d5270cc502fccb63e3c5aa2cb3be02e3c"

  strings:
    $s1  = "function methFl1(methHl4) {eval(\"/*@cc_on var methUc2 = new Date() @*/\");methUc2[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (me" ascii
    $s2  = "function methFl1(methHl4) {eval(\"/*@cc_on var methUc2 = new Date() @*/\");methUc2[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (me" ascii
    $s3  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methFl1(\";``)``\\x22``w``t``n``g``c``r``s``u``/``m``o``c``.``o``n`" ascii
    $s4  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methFl1(\"/``*``@`` ``}``;``)``(``e``s``o``l``c``.``8``g``Q``h``t``" ascii
    $s5  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methFl1(\";``\\x22``k``\\x22`` ``+`` ``\\x22``z``.``\\x22`` ``+`` `" ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methFl1(\";``)``'``/``%``P``M``E``T``%``'``(``]``'``s``g``n``i``r``" ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methFl1(\";``)``\\x22``e``m``i``j``f``t``u``u``/``m``o``c``.``o``i`" ascii
    $s8  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methFl1(\";``)``\\x22``P``T``T``H``L``M``X``.``2``L``M``X``S``M``" ascii
    $s9  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methFl1(\";``)``\\x22``P``T``T``H``L``M``X``.``2``L``M``X``S``M``" ascii
    $s10 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methFl1(\";``0``j``R``h``t``e``m`` ``+`` ``6``o``B``h``t``e``m``=``" ascii
    $s11 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methFl1(\";``\\x22``P``S``Y``a``a``L``P``Q``x``t``n``x``F``A``g``M`" ascii
    $s12 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methFl1(\";``0`` ``=`` ``8``v``Q``h``t``e``m`` ``r``a``v\"))), 1);/" ascii
    $s13 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methFl1(\"}``;``h``t``a``P``t``r``o``h``S``.``1``z``F``P``h``t``e``" ascii
    $s14 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methFl1(\";``\\x22``k``\\x22`` ``+`` ``\\x22``z``.``\\x22`` ``+`` `" ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methFl1(\"\"))), 1);///////////////////////////////////////////////" ascii
    $s16 = "UTCMilliseconds\"]()[\"toString\"](10) == \"20\") {var methUOf5 = methHl4[\"sp\"+\"lit\"](\"``\"); return methUOf5[\"reverse\"](" ascii
    $s17 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methFl1(\";``)``\\x22``s``w``y``v``g``u``2``n``s``/``r``a``.``m``o`" ascii
    $s18 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methFl1(\";``\\x22``P``S``Y``a``a``L``P``Q``x``t``n``x``F``A``g``M`" ascii
    $s19 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methFl1(\";``)``\\x22``l``l``e``h``S``.``t``p``i``r``c``S``W``\\x22" ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methFl1(\"\"))), 1);///////////////////////////////////////////////" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}