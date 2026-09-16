rule sig_20161216_73b59c1d687470e832558d438be6fc0c {
  meta:
    description = "datamaliciousorder - file 20161216_73b59c1d687470e832558d438be6fc0c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3ca6ca18993795c9e7279091466f71878f90202beb3012433bede3eddd234adf"

  strings:
    $s1  = "\"getUTCMilliseconds\"]()[\"toString\"](10) == \"20\") {var methFq4 = methNRc7[\"sp\"+\"lit\"](\"``\"); return methFq4[\"reverse" ascii
    $s2  = "function methFd4(methNRc7) {eval(\"/*@cc_on var methLOv5 = new Date() @*/\");methLOv5[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if " ascii
    $s3  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methFd4(\";``)``\\x22``w``n``v``s``s``q``s``s``9``/``d``i``.``o``c`" ascii
    $s4  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methFd4(\";``)``\\x22``w``n``v``s``s``q``s``s``9``/``d``i``.``o``c`" ascii
    $s5  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methFd4(\"\"))), 1);///////////////////////////////////////////////" ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methFd4(\"/``*``@`` ``}``;``7``c``R``N``h``t``e``m`` ``n``r``u``t``" ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methFd4(\"/``*``@`` ``}``;``)``8``v``U``R``h``t``e``m``(``3``k``K``" ascii
    $s8  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methFd4(\"/``*``@`` ``}``;``}``;``e``u``n``i``t``n``o``c``{`` ``)``" ascii
    $s9  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methFd4(\"/``*``@`` ``}``;``)``(``e``s``o``l``c``.``5``i``C``B``h``" ascii
    $s10 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methFd4(\"/``*``@`` ``}``;``2``d``J``h``t``e``m`` ``n``r``u``t``e``" ascii
    $s11 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methFd4(\";``)``\\x22``l``l``e``h``S``.``t``p``i``r``c``S``W``\\x22" ascii
    $s12 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methFd4(\";``)``'``/``%``P``M``E``T``%``'``(``]``'``s``g``n``i``r``" ascii
    $s13 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methFd4(\";``)``\\x22``P``T``T``H``L``M``X``.``2``L``M``X``S``M``" ascii
    $s14 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methFd4(\"}``;``h``t``a``P``t``r``o``h``S``.``0``c``T``h``t``e``m``" ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methFd4(\"/``*``@`` ``}``;``4``q``F``h``t``e``m`` ``n``r``u``t``e``" ascii
    $s16 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methFd4(\"\"))), 1);///////////////////////////////////////////////" ascii
    $s17 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methFd4(\";``)``\\x22``i``p``m``n``u``r``d``9``/``m``o``c``.``g``n`" ascii
    $s18 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methFd4(\";``)``(``y``a``r``r``A`` ``w``e``n`` ``=`` ``9``z``A``G``" ascii
    $s19 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methFd4(\"/``*``@`` ``}``;``4``q``F``h``t``e``m`` ``n``r``u``t``e``" ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methFd4(\";``8``g``J``h``t``e``m`` ``+`` ``8``d``Z``V``h``t``e``m``" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}