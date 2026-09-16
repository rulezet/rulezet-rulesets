rule sig_20161215_487bab66b0e00385485b19c899433762 {
  meta:
    description = "datamaliciousorder - file 20161215_487bab66b0e00385485b19c899433762.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c788a287343ae52722c8f7338b400f1a0761f656e12aed0fb22c9109032ce735"

  strings:
    $s1  = "20\");if (cheburgenBl8[\"getUTCMilliseconds\"]()[\"toString\"](10) == \"20\") {var cheburgenLj4 = cheburgenRg9[\"split\"](\"``\"" ascii
    $s2  = "function cheburgenKYn6(cheburgenRg9) {eval(\"/*@cc_on var cheburgenBl8 = new Date() @*/\");cheburgenBl8[\"setUTC\"+\"Seconds\"](" ascii
    $s3  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenKYn6(\";``7``u``K``n``e``g``r``u``b``e``h``c`` ``+`` ``9``q``O" ascii
    $s4  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenKYn6(\";``\\x22``X``J``j``u``b``1``g``I``x``1``y``m``N``O``l``" ascii
    $s5  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenKYn6(\";``)``\\x22``\\x22`` ``+`` ``9``n``O``n``e``g``r``u``b`" ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenKYn6(\";``)``'``/``%``P``M``E``T``%``'``(``]``'``s``g``n``i``r" ascii
    $s7  = "heburgenLj4[\"reverse\"]().join(\"\");} else return \"\";};" fullword ascii
    $s8  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenKYn6(\";``\\x22``/``\\x22``+``\\x22``/``\\x22``+``\\x22``:``" ascii
    $s9  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenKYn6(\";``)``\\x22``\\x22`` ``+`` ``9``n``O``n``e``g``r``u``b`" ascii
    $s10 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenKYn6(\";``)``(``y``a``r``r``A`` ``w``e``n`` ``=`` ``8``c``F``n" ascii
    $s11 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenKYn6(\"/``*``@`` ``}``;``)``6``g``V``D``n``e``g``r``u``b``e``h" ascii
    $s12 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenKYn6(\";``)``\\x22``i``7``l``h``0``n``h``/``m``o``c``.``z``i``" ascii
    $s13 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenKYn6(\";``\\x22``k``\\x22`` ``+`` ``\\x22``z``.``\\x22`` ``+``" ascii
    $s14 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenKYn6(\";``\\x22``/``\\x22``+``\\x22``/``\\x22``+``\\x22``:``" ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenKYn6(\";``)``\\x22``e``w``o``b``h``/``m``o``c``.``8``6``o``h``" ascii
    $s16 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenKYn6(\";``)``\\x22``e``w``o``b``h``/``m``o``c``.``8``6``o``h``" ascii
    $s17 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenKYn6(\"/``*``@`` ``}``;``4``j``L``n``e``g``r``u``b``e``h``c`` " ascii
    $s18 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenKYn6(\"/``*``@`` ``}``;``9``g``R``n``e``g``r``u``b``e``h``c`` " ascii
    $s19 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenKYn6(\";``0`` ``=`` ``7``z``W``F``n``e``g``r``u``b``e``h``c`` " ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenKYn6(\";``)``\\x22``i``7``l``h``0``n``h``/``m``o``c``.``z``i``" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}