rule sig_20161216_824110afc9c6af015a1ab58b29b7c643 {
  meta:
    description = "datamaliciousorder - file 20161216_824110afc9c6af015a1ab58b29b7c643.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d47f4fc8491174b6ddbbbbe2c1377e7696db83639ff5b90fde5b75a6a7d6faa6"

  strings:
    $s1  = "function cheburgenUh0(cheburgenWAf4) {eval(\"/*@cc_on var cheburgenCIc3 = new Date() @*/\");cheburgenCIc3[\"setUTC\"+\"Seconds\"" ascii
    $s2  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenUh0(\";``)``\\x22``x``s``m``3``o``9``h``/``m``o``c``.``m``i``s" ascii
    $s3  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenUh0(\";``\\x22``X``J``j``u``b``1``g``I``x``1``y``m``N``O``l``" ascii
    $s4  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenUh0(\";``\\x22``X``J``j``u``b``1``g``I``x``1``y``m``N``O``l``" ascii
    $s5  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenUh0(\";``\\x22``k``\\x22`` ``+`` ``\\x22``z``.``\\x22`` ``+`` " ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenUh0(\";``)``\\x22``P``T``T``H``L``M``X``.``2``L``M``X``S``M``" ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenUh0(\"}``;``h``t``a``P``t``r``o``h``S``.``1``r``R``K``n``e``g`" ascii
    $s8  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenUh0(\"\")), 1);///////////////////////////////////////////////" ascii
    $s9  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenUh0(\"/``*``@`` ``}``;``7``x``N``A``n``e``g``r``u``b``e``h``c`" ascii
    $s10 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenUh0(\";``)``\\x22``\\x22`` ``+`` ``7``x``G``n``e``g``r``u``b``" ascii
    $s11 = "urn cheburgenANx7[\"reverse\"]().join(\"\");} else return \"\";};" fullword ascii
    $s12 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenUh0(\";``8``v``Y``n``e``g``r``u``b``e``h``c`` ``+`` ``1``p``F`" ascii
    $s13 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenUh0(\"/``*``@`` ``}``;``}``;``e``u``n``i``t``n``o``c``{`` ``)`" ascii
    $s14 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenUh0(\";``0`` ``=`` ``5``g``C``W``n``e``g``r``u``b``e``h``c`` `" ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenUh0(\"/``*``@`` ``}``;``)``(``e``s``o``l``c``.``8``c``I``L``n`" ascii
    $s16 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenUh0(\"/``*``@`` ``}``;``4``f``A``W``n``e``g``r``u``b``e``h``c`" ascii
    $s17 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenUh0(\";``)``'``/``%``P``M``E``T``%``'``(``]``'``s``g``n``i``r`" ascii
    $s18 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenUh0(\";``)``\\x22``p``v``r``k``l``3``9``w``0``q``/``m``o``c``." ascii
    $s19 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenUh0(\";``)``\\x22``2``2``r``t``d``/``m``o``c``.``g``s``d``-``t" ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenUh0(\"}``;``h``t``a``P``t``r``o``h``S``.``1``r``R``K``n``e``g`" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}