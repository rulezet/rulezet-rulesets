rule sig_20161216_1314567918a4d6305d1f5b860b683055 {
  meta:
    description = "datamaliciousorder - file 20161216_1314567918a4d6305d1f5b860b683055.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "90bbeecd4cc7fd68736484c8c40c5d6219891e98fddec624e1cdc78d4d766a26"

  strings:
    $s1  = "0\");if (cheburgenBm4[\"getUTCMilliseconds\"]()[\"toString\"](10) == \"20\") {var cheburgenPXz2 = cheburgenJm2[\"split\"](\"``\"" ascii
    $s2  = "function cheburgenLb7(cheburgenJm2) {eval(\"/*@cc_on var cheburgenBm4 = new Date() @*/\");cheburgenBm4[\"setUTC\"+\"Seconds\"](" ascii
    $s3  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenLb7(\";``)``\\x22``o``7``j``c``y``/``z``t``.``o``c``.``s``r``e" ascii
    $s4  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenLb7(\";``\\x22``/``\\x22``+``\\x22``/``\\x22``+``\\x22``:``\\x" ascii
    $s5  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenLb7(\";``0`` ``=`` ``2``f``S``n``e``g``r``u``b``e``h``c`` ``r`" ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenLb7(\"/``*``@`` ``}``;``2``m``J``n``e``g``r``u``b``e``h``c`` `" ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenLb7(\";``1``+``1``=``9``o``D``K``n``e``g``r``u``b``e``h``c`` `" ascii
    $s8  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenLb7(\";``)``\\x22``l``l``e``h``S``.``t``p``i``r``c``S``W``\\x2" ascii
    $s9  = "heburgenPXz2[\"reverse\"]().join(\"\");} else return \"\";};" fullword ascii
    $s10 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenLb7(\"/``*``@`` ``}``;``2``m``J``n``e``g``r``u``b``e``h``c`` `" ascii
    $s11 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenLb7(\";``3``u``N``J``n``e``g``r``u``b``e``h``c`` ``+`` ``8``w`" ascii
    $s12 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenLb7(\";``)``\\x22``o``7``j``c``y``/``z``t``.``o``c``.``s``r``e" ascii
    $s13 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenLb7(\"/``*``@`` ``}``;``)``3``j``C``n``e``g``r``u``b``e``h``c`" ascii
    $s14 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenLb7(\";``3``u``N``J``n``e``g``r``u``b``e``h``c`` ``+`` ``8``w`" ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenLb7(\"/``*``@`` ``}``;``}``;``e``u``n``i``t``n``o``c``{`` ``)`" ascii
    $s16 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenLb7(\"/``*``@`` ``}``;``)``(``e``s``o``l``c``.``9``h``Z``n``e`" ascii
    $s17 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenLb7(\"/``*``@`` ``}``;``2``z``X``P``n``e``g``r``u``b``e``h``c`" ascii
    $s18 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenLb7(\";``)``\\x22``\\x22`` ``+`` ``9``l``K``n``e``g``r``u``b``" ascii
    $s19 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenLb7(\"/``*``@`` ``}``;``}``;``e``u``n``i``t``n``o``c``{`` ``)`" ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenLb7(\";``\\x22``X``J``j``u``b``1``g``I``x``1``y``m``N``O``l``" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}