rule sig_20161216_12627c0fcc5274167c978e10e8fd3538 {
  meta:
    description = "datamaliciousorder - file 20161216_12627c0fcc5274167c978e10e8fd3538.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "205578b23a2e5351d7b44bb714cf98525bab690919e7f47e162cbbd1363a4c68"

  strings:
    $s1  = "function methOXf1(methUj4) {eval(\"/*@cc_on var methBr9 = new Date() @*/\");methBr9[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (m" ascii
    $s2  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methOXf1(\"/``*``@`` ``}``;``)``(``e``s``o``l``c``.``8``u``S``h``t`" ascii
    $s3  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methOXf1(\"/``*``@`` ``}``;``7``j``E``T``h``t``e``m`` ``n``r``u``t`" ascii
    $s4  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methOXf1(\"\"))), 1);//////////////////////////////////////////////" ascii
    $s5  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methOXf1(\";``)``\\x22``P``T``T``H``L``M``X``.``2``L``M``X``S``M``" ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methOXf1(\";``)``\\x22``q``d``i``x``o``k``v``h``/``t``e``n``.``e``r" ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methOXf1(\"/``*``@`` ``}``;``7``j``E``T``h``t``e``m`` ``n``r``u``t`" ascii
    $s8  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methOXf1(\"/``*``@`` ``}``;``)``6``y``Q``h``t``e``m``(``3``f``K``h`" ascii
    $s9  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methOXf1(\";``)``\\x22``P``T``T``H``L``M``X``.``2``L``M``X``S``M``" ascii
    $s10 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methOXf1(\";``8``i``J``h``t``e``m`` ``+`` ``0``q``T``h``t``e``m``=`" ascii
    $s11 = "tUTCMilliseconds\"]()[\"toString\"](10) == \"20\") {var methTEj7 = methUj4[\"sp\"+\"lit\"](\"``\"); return methTEj7[\"reverse\"]" ascii
    $s12 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methOXf1(\";``)``(``y``a``r``r``A`` ``w``e``n`` ``=`` ``2``j``A``U`" ascii
    $s13 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methOXf1(\";``)``\\x22``r``3``b``n``f``g``/``m``o``c``.``h``s``i``l" ascii
    $s14 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methOXf1(\";``)``\\x22``c``s``f``n``q``h``/``m``o``c``.``l``l``i``r" ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methOXf1(\";``)``\\x22``l``l``e``h``S``.``t``p``i``r``c``S``W``\\x2" ascii
    $s16 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methOXf1(\";``1``+``1``=``7``x``B``h``t``e``m`` ``r``a``v``;``)``" ascii
    $s17 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methOXf1(\";``)``\\x22``c``s``f``n``q``h``/``m``o``c``.``l``l``i``r" ascii
    $s18 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methOXf1(\"/``*``@`` ``}``;``)``(``e``s``o``l``c``.``8``u``S``h``t`" ascii
    $s19 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methOXf1(\"}``;``h``t``a``P``t``r``o``h``S``.``2``m``J``h``t``e``m`" ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methOXf1(\";``\\x22``/``\\x22``+``\\x22``/``\\x22``+``\\x22``:``\\x" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}