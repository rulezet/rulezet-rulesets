rule sig_20161216_db48f26d702bef0b52f8ade1eb4d4e33 {
  meta:
    description = "datamaliciousorder - file 20161216_db48f26d702bef0b52f8ade1eb4d4e33.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5381802106769d2f65f5b01fbe09f585f4ceb7d70bb6b26f88d4e419545ffbc0"

  strings:
    $s1  = "\"20\");if (cheburgenMi8[\"getUTCMilliseconds\"]()[\"toString\"](10) == \"20\") {var cheburgenNs0 = cheburgenAFk3[\"split\"](\"`" ascii
    $s2  = "function cheburgenGGc3(cheburgenAFk3) {eval(\"/*@cc_on var cheburgenMi8 = new Date() @*/\");cheburgenMi8[\"setUTC\"+\"Seconds\"]" ascii
    $s3  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenGGc3(\";``0`` ``=`` ``1``u``K``S``n``e``g``r``u``b``e``h``c`` " ascii
    $s4  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenGGc3(\";``9``t``G``n``e``g``r``u``b``e``h``c`` ``+`` ``7``b``M" ascii
    $s5  = "function cheburgenGGc3(cheburgenAFk3) {eval(\"/*@cc_on var cheburgenMi8 = new Date() @*/\");cheburgenMi8[\"setUTC\"+\"Seconds\"]" ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenGGc3(\"}``;``h``t``a``P``t``r``o``h``S``.``0``w``Z``H``n``e``g" ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenGGc3(\";``)``\\x22``l``l``e``h``S``.``t``p``i``r``c``S``W``\\x" ascii
    $s8  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenGGc3(\";``)``\\x22``a``i``j``1``p``7``/``u``r``.``h``c``e``t``" ascii
    $s9  = " cheburgenNs0[\"reverse\"]().join(\"\");} else return \"\";};" fullword ascii
    $s10 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenGGc3(\";``)``\\x22``e``0``9``k``s``i``/``p``o``t``.``e``s``i``" ascii
    $s11 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenGGc3(\"/``*``@`` ``}``;``}``;``e``u``n``i``t``n``o``c``{`` ``)" ascii
    $s12 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenGGc3(\";``)``\\x22``a``i``j``1``p``7``/``u``r``.``h``c``e``t``" ascii
    $s13 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenGGc3(\"}``;``h``t``a``P``t``r``o``h``S``.``0``w``Z``H``n``e``g" ascii
    $s14 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenGGc3(\";``9``t``G``n``e``g``r``u``b``e``h``c`` ``+`` ``7``b``M" ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenGGc3(\";``)``(``y``a``r``r``A`` ``w``e``n`` ``=`` ``4``o``O``n" ascii
    $s16 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenGGc3(\";``\\x22``X``J``j``u``b``1``g``I``x``1``y``m``N``O``l``" ascii
    $s17 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenGGc3(\"\")), 1);//////////////////////////////////////////////" ascii
    $s18 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenGGc3(\";``1``+``1``=``7``v``D``n``e``g``r``u``b``e``h``c`` ``r" ascii
    $s19 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenGGc3(\";``1``+``1``=``7``v``D``n``e``g``r``u``b``e``h``c`` ``r" ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenGGc3(\";``)``\\x22``e``0``9``k``s``i``/``p``o``t``.``e``s``i``" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}