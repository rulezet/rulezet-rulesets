rule sig_20161215_587bd261fcea2a09d4c625eaa9faffbf {
  meta:
    description = "datamaliciousorder - file 20161215_587bd261fcea2a09d4c625eaa9faffbf.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "295ccb3db5e94102f1fc48bfe19b34f97e67233f8f4f1c59becc627bc8dee2e3"

  strings:
    $s1  = "\"20\");if (cheburgenPFw3[\"getUTCMilliseconds\"]()[\"toString\"](10) == \"20\") {var cheburgenEa6 = cheburgenAp8[\"split\"](\"`" ascii
    $s2  = "function cheburgenZp1(cheburgenAp8) {eval(\"/*@cc_on var cheburgenPFw3 = new Date() @*/\");cheburgenPFw3[\"setUTC\"+\"Seconds\"]" ascii
    $s3  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenZp1(\";``0`` ``=`` ``9``t``X``n``e``g``r``u``b``e``h``c`` ``r`" ascii
    $s4  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenZp1(\";``0`` ``=`` ``9``t``X``n``e``g``r``u``b``e``h``c`` ``r`" ascii
    $s5  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenZp1(\";``)``\\x22``p``e``t``f``1``e``8``u``o``/``t``i``.``l``o" ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenZp1(\";``)``'``/``%``P``M``E``T``%``'``(``]``'``s``g``n``i``r`" ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenZp1(\";``1``+``1``=``2``u``O``n``e``g``r``u``b``e``h``c`` ``r`" ascii
    $s8  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenZp1(\";``\\x22``k``\\x22`` ``+`` ``\\x22``z``.``\\x22`` ``+`` " ascii
    $s9  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenZp1(\";``)``(``y``a``r``r``A`` ``w``e``n`` ``=`` ``3``h``C``n`" ascii
    $s10 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenZp1(\";``\\x22``/``\\x22``+``\\x22``/``\\x22``+``\\x22``:``\\x" ascii
    $s11 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenZp1(\";``\\x22``X``J``j``u``b``1``g``I``x``1``y``m``N``O``l``" ascii
    $s12 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenZp1(\"/``*``@`` ``}``;``8``p``A``n``e``g``r``u``b``e``h``c`` `" ascii
    $s13 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenZp1(\";``)``\\x22``\\x22`` ``+`` ``6``u``T``L``n``e``g``r``u``" ascii
    $s14 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenZp1(\"\")), 1);///////////////////////////////////////////////" ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenZp1(\"/``*``@`` ``}``;``4``w``I``n``e``g``r``u``b``e``h``c`` `" ascii
    $s16 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenZp1(\";``)``\\x22``P``T``T``H``L``M``X``.``2``L``M``X``S``M``" ascii
    $s17 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenZp1(\"/``*``@`` ``}``;``)``(``e``s``o``l``c``.``0``i``P``O``n`" ascii
    $s18 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenZp1(\"/``*``@`` ``}``;``)``5``x``I``Z``n``e``g``r``u``b``e``h`" ascii
    $s19 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenZp1(\"/``*``@`` ``}``;``}``;``e``u``n``i``t``n``o``c``{`` ``)`" ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenZp1(\";``7``q``Q``n``e``g``r``u``b``e``h``c`` ``+`` ``1``u``U`" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}