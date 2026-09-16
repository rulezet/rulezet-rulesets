rule sig_20161216_862cfef1f31b886f6c2914792d28e5ca {
  meta:
    description = "datamaliciousorder - file 20161216_862cfef1f31b886f6c2914792d28e5ca.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "63d1d311daff995da273357917e8b58b31a96a723d1b2bf4fe97a47d1f666711"

  strings:
    $s1  = "[\"getUTCMilliseconds\"]()[\"toString\"](10) == \"20\") {var methUPa1 = methNGw5[\"sp\"+\"lit\"](\"``\"); return methUPa1[\"reve" ascii
    $s2  = "function methYHm1(methNGw5) {eval(\"/*@cc_on var methRAg1 = new Date() @*/\");methRAg1[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if" ascii
    $s3  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methYHm1(\"/``*``@`` ``}``;``5``w``G``N``h``t``e``m`` ``n``r``u``t`" ascii
    $s4  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methYHm1(\"/``*``@`` ``}``;``)``8``f``S``h``t``e``m``(``5``z``G``h`" ascii
    $s5  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methYHm1(\"/``*``@`` ``}``;``}``;``e``u``n``i``t``n``o``c``{`` ``)`" ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methYHm1(\"/``*``@`` ``}``;``}``;``e``u``n``i``t``n``o``c``{`` ``)`" ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methYHm1(\";``)``\\x22``0``g``d``u``k``c``j``/``t``i``.``i``l``i``b" ascii
    $s8  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methYHm1(\"/``*``@`` ``}``;``)``(``e``s``o``l``c``.``7``t``F``h``t`" ascii
    $s9  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methYHm1(\";``)``(``y``a``r``r``A`` ``w``e``n`` ``=`` ``1``o``O``B`" ascii
    $s10 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methYHm1(\"}``;``h``t``a``P``t``r``o``h``S``.``2``p``L``h``t``e``m`" ascii
    $s11 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methYHm1(\"/``*``@`` ``}``;``)``(``e``s``o``l``c``.``7``t``F``h``t`" ascii
    $s12 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methYHm1(\";``\\x22``k``\\x22`` ``+`` ``\\x22``z``.``\\x22`` ``+`` " ascii
    $s13 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methYHm1(\";``)``\\x22``P``T``T``H``L``M``X``.``2``L``M``X``S``M``" ascii
    $s14 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methYHm1(\";``\\x22``P``S``Y``a``a``L``P``Q``x``t``n``x``F``A``g``M" ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methYHm1(\";``)``'``/``%``P``M``E``T``%``'``(``]``'``s``g``n``i``r`" ascii
    $s16 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methYHm1(\"/``*``@`` ``}``;``5``w``G``N``h``t``e``m`` ``n``r``u``t`" ascii
    $s17 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methYHm1(\";``)``\\x22``l``l``e``h``S``.``t``p``i``r``c``S``W``\\x2" ascii
    $s18 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methYHm1(\";``\\x22``k``\\x22`` ``+`` ``\\x22``z``.``\\x22`` ``+`` " ascii
    $s19 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methYHm1(\"/``*``@`` ``}``;``)``8``f``S``h``t``e``m``(``5``z``G``h`" ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methYHm1(\"/``*``@`` ``}``;``8``q``N``h``t``e``m`` ``n``r``u``t``e`" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}