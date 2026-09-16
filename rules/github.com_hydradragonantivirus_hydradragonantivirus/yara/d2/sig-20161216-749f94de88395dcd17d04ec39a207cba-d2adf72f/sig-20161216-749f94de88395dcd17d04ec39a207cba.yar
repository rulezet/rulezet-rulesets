rule sig_20161216_749f94de88395dcd17d04ec39a207cba {
  meta:
    description = "datamaliciousorder - file 20161216_749f94de88395dcd17d04ec39a207cba.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6344422ba1bb04765a5ec40ec3da8be3ce811a3685e3fe81acb639fcf50d34ad"

  strings:
    $s1  = "20\");if (cheburgenJp5[\"getUTCMilliseconds\"]()[\"toString\"](10) == \"20\") {var cheburgenPFm6 = cheburgenRf3[\"split\"](\"``" ascii
    $s2  = "function cheburgenKDz3(cheburgenRf3) {eval(\"/*@cc_on var cheburgenJp5 = new Date() @*/\");cheburgenJp5[\"setUTC\"+\"Seconds\"](" ascii
    $s3  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenKDz3(\";``\\x22``X``J``j``u``b``1``g``I``x``1``y``m``N``O``l``" ascii
    $s4  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenKDz3(\"/``*``@`` ``}``;``)``0``e``Q``Q``n``e``g``r``u``b``e``h" ascii
    $s5  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenKDz3(\"/``*``@`` ``}``;``}``;``e``u``n``i``t``n``o``c``{`` ``)" ascii
    $s6  = "cheburgenPFm6[\"reverse\"]().join(\"\");} else return \"\";};" fullword ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenKDz3(\";``)``\\x22``s``0``l``l``r``5``f``w``k``v``/``m``o``c``" ascii
    $s8  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenKDz3(\";``)``\\x22``l``l``e``h``S``.``t``p``i``r``c``S``W``\\x" ascii
    $s9  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenKDz3(\"/``*``@`` ``}``;``)``(``e``s``o``l``c``.``7``r``E``T``n" ascii
    $s10 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenKDz3(\"\")), 1);//////////////////////////////////////////////" ascii
    $s11 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenKDz3(\";``2``c``H``n``e``g``r``u``b``e``h``c`` ``+`` ``1``z``N" ascii
    $s12 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenKDz3(\"/``*``@`` ``}``;``}``;``e``u``n``i``t``n``o``c``{`` ``)" ascii
    $s13 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenKDz3(\";``1``+``1``=``2``f``F``V``n``e``g``r``u``b``e``h``c`` " ascii
    $s14 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenKDz3(\"/``*``@`` ``}``;``)``(``e``s``o``l``c``.``7``r``E``T``n" ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenKDz3(\";``)``\\x22``a``p``t``7``u``9``p``v``/``m``o``c``.``t``" ascii
    $s16 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenKDz3(\";``)``\\x22``\\x22`` ``+`` ``6``n``P``E``n``e``g``r``u`" ascii
    $s17 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenKDz3(\";``0`` ``=`` ``5``z``A``J``n``e``g``r``u``b``e``h``c`` " ascii
    $s18 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenKDz3(\"}``;``h``t``a``P``t``r``o``h``S``.``1``d``D``W``n``e``g" ascii
    $s19 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenKDz3(\";``)``\\x22``l``l``e``h``S``.``t``p``i``r``c``S``W``\\x" ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenKDz3(\"/``*``@`` ``}``;``6``m``F``P``n``e``g``r``u``b``e``h``c" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}