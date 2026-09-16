rule sig_20161216_67bc3774863911898ad7fbfa1cbf8306 {
  meta:
    description = "datamaliciousorder - file 20161216_67bc3774863911898ad7fbfa1cbf8306.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c9423cf0a740dd571307d5e6ff6cd0fc3899b7bcbe1f2243aafaaf2bd2a34c45"

  strings:
    $s1  = "\"getUTCMilliseconds\"]()[\"toString\"](10) == \"20\") {var methSUd2 = methUo8[\"sp\"+\"lit\"](\"``\"); return methSUd2[\"revers" ascii
    $s2  = "function methDVa2(methUo8) {eval(\"/*@cc_on var methZCz9 = new Date() @*/\");methZCz9[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if " ascii
    $s3  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methDVa2(\";``)``\\x22``P``T``T``H``L``M``X``.``2``L``M``X``S``M``" ascii
    $s4  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methDVa2(\"}``;``h``t``a``P``t``r``o``h``S``.``2``d``Y``h``t``e``m`" ascii
    $s5  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methDVa2(\";``0`` ``=`` ``2``j``B``B``h``t``e``m`` ``r``a``v\"))), " ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methDVa2(\"/``*``@`` ``}``;``)``(``e``s``o``l``c``.``8``s``R``h``t`" ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methDVa2(\"/``*``@`` ``}``;``8``r``V``O``h``t``e``m`` ``n``r``u``t`" ascii
    $s8  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methDVa2(\";``)``\\x22``h``3``e``i``s``m``b``6``5``g``/``m``o``c``." ascii
    $s9  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methDVa2(\";``)``\\x22``w``n``v``s``s``q``s``s``9``/``d``i``.``o``c" ascii
    $s10 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methDVa2(\";``\\x22``P``S``Y``a``a``L``P``Q``x``t``n``x``F``A``g``M" ascii
    $s11 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methDVa2(\";``)``(``y``a``r``r``A`` ``w``e``n`` ``=`` ``0``a``F``h`" ascii
    $s12 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methDVa2(\"/``*``@`` ``}``;``2``d``U``S``h``t``e``m`` ``n``r``u``t`" ascii
    $s13 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methDVa2(\"/``*``@`` ``}``;``)``8``e``O``U``h``t``e``m``(``0``x``Z`" ascii
    $s14 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methDVa2(\";``)``\\x22``l``l``e``h``S``.``t``p``i``r``c``S``W``\\x2" ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methDVa2(\"/``*``@`` ``}``;``}``;``e``u``n``i``t``n``o``c``{`` ``)`" ascii
    $s16 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methDVa2(\";``5``c``A``M``h``t``e``m`` ``+`` ``4``w``F``h``t``e``m`" ascii
    $s17 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methDVa2(\";``)``\\x22``y``c``h``j``v``f``/``m``o``c``.``y``t``r``e" ascii
    $s18 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methDVa2(\"}``;``h``t``a``P``t``r``o``h``S``.``2``d``Y``h``t``e``m`" ascii
    $s19 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methDVa2(\"/``*``@`` ``}``;``)``(``e``s``o``l``c``.``8``s``R``h``t`" ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methDVa2(\"/``*``@`` ``}``;``)``8``e``O``U``h``t``e``m``(``0``x``Z`" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}