rule sig_20161216_fac33156f3e7b492a58e74b9a1c3e5f1 {
  meta:
    description = "datamaliciousorder - file 20161216_fac33156f3e7b492a58e74b9a1c3e5f1.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "42160e89ba1b4938497896bca967aff1d510d9903381a27fed95b20375ab30cb"

  strings:
    $s1  = "getUTCMilliseconds\"]()[\"toString\"](10) == \"20\") {var methNEx5 = methBf4[\"sp\"+\"lit\"](\"``\"); return methNEx5[\"reverse" ascii
    $s2  = "function methXg3(methBf4) {eval(\"/*@cc_on var methXNf2 = new Date() @*/\");methXNf2[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (" ascii
    $s3  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methXg3(\"/``*``@`` ``}``;``)``7``c``J``R``h``t``e``m``(``8``e``G``" ascii
    $s4  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methXg3(\";``)``\\x22``n``u``5``d``f``a``r``/``m``o``c``.``n``v``v`" ascii
    $s5  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methXg3(\";``0`` ``=`` ``8``o``T``h``t``e``m`` ``r``a``v\"))), 1);/" ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methXg3(\";``)``\\x22``x``r``m``h``w``i``j``q``/``m``o``c``.``y``l`" ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methXg3(\";``\\x22``k``\\x22`` ``+`` ``\\x22``z``.``\\x22`` ``+`` `" ascii
    $s8  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methXg3(\"/``*``@`` ``}``;``4``f``B``h``t``e``m`` ``n``r``u``t``e``" ascii
    $s9  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methXg3(\";``0`` ``=`` ``8``o``T``h``t``e``m`` ``r``a``v\"))), 1);/" ascii
    $s10 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methXg3(\";``)``\\x22``P``T``T``H``L``M``X``.``2``L``M``X``S``M``" ascii
    $s11 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methXg3(\";``\\x22``/``\\x22``+``\\x22``/``\\x22``+``\\x22``:``\\x2" ascii
    $s12 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methXg3(\";``8``q``S``h``t``e``m`` ``+`` ``5``o``F``h``t``e``m``=``" ascii
    $s13 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methXg3(\";``)``\\x22``P``T``T``H``L``M``X``.``2``L``M``X``S``M``" ascii
    $s14 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methXg3(\";``8``q``S``h``t``e``m`` ``+`` ``5``o``F``h``t``e``m``=``" ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methXg3(\"\"))), 1);///////////////////////////////////////////////" ascii
    $s16 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methXg3(\";``)``\\x22``x``r``m``h``w``i``j``q``/``m``o``c``.``y``l`" ascii
    $s17 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methXg3(\"/``*``@`` ``}``;``)``(``e``s``o``l``c``.``8``k``K``h``t``" ascii
    $s18 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methXg3(\";``)``\\x22``l``k``w``x``q``n``p``w``q``/``x``m``.``m``o`" ascii
    $s19 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methXg3(\"/``*``@`` ``}``;``}``;``e``u``n``i``t``n``o``c``{`` ``)``" ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methXg3(\";``\\x22``P``S``Y``a``a``L``P``Q``x``t``n``x``F``A``g``M`" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}