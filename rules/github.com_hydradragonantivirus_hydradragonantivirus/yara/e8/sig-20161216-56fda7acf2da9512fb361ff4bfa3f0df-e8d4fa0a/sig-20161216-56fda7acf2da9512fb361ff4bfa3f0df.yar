rule sig_20161216_56fda7acf2da9512fb361ff4bfa3f0df {
  meta:
    description = "datamaliciousorder - file 20161216_56fda7acf2da9512fb361ff4bfa3f0df.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "162a7302f110e4f459cae951c060eb316561fc30ca783a5dbdf656e2305d1af0"

  strings:
    $s1  = "function cheburgenGs2(cheburgenDh4) {eval(\"/*@cc_on var cheburgenTBz5 = new Date() @*/\");cheburgenTBz5[\"setUTC\"+\"Seconds\"]" ascii
    $s2  = "\"20\");if (cheburgenTBz5[\"getUTCMilliseconds\"]()[\"toString\"](10) == \"20\") {var cheburgenAf8 = cheburgenDh4[\"split\"](\"`" ascii
    $s3  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenGs2(\";``)``\\x22``n``p``u``a``b``u``/``g``r``o``.``e``v``i``t" ascii
    $s4  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenGs2(\";``)``\\x22``\\x22`` ``+`` ``2``l``X``G``n``e``g``r``u``" ascii
    $s5  = "function cheburgenGs2(cheburgenDh4) {eval(\"/*@cc_on var cheburgenTBz5 = new Date() @*/\");cheburgenTBz5[\"setUTC\"+\"Seconds\"]" ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenGs2(\";``)``\\x22``P``T``T``H``L``M``X``.``2``L``M``X``S``M``" ascii
    $s7  = " cheburgenAf8[\"reverse\"]().join(\"\");} else return \"\";};" fullword ascii
    $s8  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenGs2(\"}``;``h``t``a``P``t``r``o``h``S``.``2``e``Y``U``n``e``g`" ascii
    $s9  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenGs2(\";``\\x22``X``J``j``u``b``1``g``I``x``1``y``m``N``O``l``" ascii
    $s10 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenGs2(\"/``*``@`` ``}``;``}``;``e``u``n``i``t``n``o``c``{`` ``)`" ascii
    $s11 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenGs2(\";``)``'``/``%``P``M``E``T``%``'``(``]``'``s``g``n``i``r`" ascii
    $s12 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenGs2(\"/``*``@`` ``}``;``)``8``a``M``n``e``g``r``u``b``e``h``c`" ascii
    $s13 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenGs2(\"\")), 1);///////////////////////////////////////////////" ascii
    $s14 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenGs2(\"/``*``@`` ``}``;``9``m``F``H``n``e``g``r``u``b``e``h``c`" ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenGs2(\"}``;``h``t``a``P``t``r``o``h``S``.``2``e``Y``U``n``e``g`" ascii
    $s16 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenGs2(\";``)``\\x22``h``h``3``m``u``5``e``z``t``/``m``o``c``.``c" ascii
    $s17 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenGs2(\";``)``\\x22``h``h``3``m``u``5``e``z``t``/``m``o``c``.``c" ascii
    $s18 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenGs2(\"/``*``@`` ``}``;``}``;``e``u``n``i``t``n``o``c``{`` ``)`" ascii
    $s19 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenGs2(\";``)``\\x22``l``l``e``h``S``.``t``p``i``r``c``S``W``\\x2" ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenGs2(\";``\\x22``/``\\x22``+``\\x22``/``\\x22``+``\\x22``:``\\x" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}