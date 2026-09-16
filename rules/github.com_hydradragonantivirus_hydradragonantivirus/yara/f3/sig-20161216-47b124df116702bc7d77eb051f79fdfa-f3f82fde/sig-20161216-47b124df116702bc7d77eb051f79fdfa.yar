rule sig_20161216_47b124df116702bc7d77eb051f79fdfa {
  meta:
    description = "datamaliciousorder - file 20161216_47b124df116702bc7d77eb051f79fdfa.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2be97965e06102274ec7433c2795b160acec3bf8b897e8a71d0baec63d6a5eb6"

  strings:
    $s1  = "function methATm3(methYTx6) {eval(\"/*@cc_on var methDJn9 = new Date() @*/\");methDJn9[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if" ascii
    $s2  = "[\"getUTCMilliseconds\"]()[\"toString\"](10) == \"20\") {var methETd8 = methYTx6[\"sp\"+\"lit\"](\"``\"); return methETd8[\"reve" ascii
    $s3  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methATm3(\";``\\x22``P``S``Y``a``a``L``P``Q``x``t``n``x``F``A``g``M" ascii
    $s4  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methATm3(\";``)``\\x22``q``d``i``x``o``k``v``h``/``t``e``n``.``e``r" ascii
    $s5  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methATm3(\";``7``o``G``W``h``t``e``m`` ``+`` ``6``a``F``h``t``e``m`" ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methATm3(\"/``*``@`` ``}``;``)``(``e``s``o``l``c``.``0``c``R``O``h`" ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methATm3(\";``1``+``1``=``3``y``J``G``h``t``e``m`` ``r``a``v``;``)`" ascii
    $s8  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methATm3(\";``0`` ``=`` ``4``x``Q``h``t``e``m`` ``r``a``v\"))), 1);" ascii
    $s9  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methATm3(\";``)``\\x22``r``3``b``n``f``g``/``m``o``c``.``h``s``i``l" ascii
    $s10 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methATm3(\"\"))), 1);//////////////////////////////////////////////" ascii
    $s11 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methATm3(\";``)``\\x22``P``T``T``H``L``M``X``.``2``L``M``X``S``M``" ascii
    $s12 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methATm3(\";``\\x22``k``\\x22`` ``+`` ``\\x22``z``.``\\x22`` ``+`` " ascii
    $s13 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methATm3(\"/``*``@`` ``}``;``)``4``m``D``h``t``e``m``(``2``m``D``U`" ascii
    $s14 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methATm3(\";``)``\\x22``r``3``b``n``f``g``/``m``o``c``.``h``s``i``l" ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methATm3(\";``)``\\x22``q``d``i``x``o``k``v``h``/``t``e``n``.``e``r" ascii
    $s16 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methATm3(\"}``;``h``t``a``P``t``r``o``h``S``.``4``w``J``h``t``e``m`" ascii
    $s17 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methATm3(\"/``*``@`` ``}``;``}``;``e``u``n``i``t``n``o``c``{`` ``)`" ascii
    $s18 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methATm3(\";``)``\\x22``q``g``p``l``c``i``d``g``/``r``i``.``i``h``g" ascii
    $s19 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methATm3(\";``)``\\x22``l``l``e``h``S``.``t``p``i``r``c``S``W``\\x2" ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methATm3(\";``)``\\x22``c``s``f``n``q``h``/``m``o``c``.``l``l``i``r" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}