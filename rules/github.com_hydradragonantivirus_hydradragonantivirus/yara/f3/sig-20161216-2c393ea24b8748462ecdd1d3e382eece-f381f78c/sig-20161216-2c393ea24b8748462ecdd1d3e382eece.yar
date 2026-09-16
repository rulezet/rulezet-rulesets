rule sig_20161216_2c393ea24b8748462ecdd1d3e382eece {
  meta:
    description = "datamaliciousorder - file 20161216_2c393ea24b8748462ecdd1d3e382eece.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "26672dc86c28a1e8dbf4d908f866db7e63fc3353e935137295d30798c5590dc0"

  strings:
    $s1  = "function cheburgenODz9(cheburgenLKe2) {eval(\"/*@cc_on var cheburgenHKi1 = new Date() @*/\");cheburgenHKi1[\"setUTC\"+\"Seconds" ascii
    $s2  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenODz9(\"/``*``@`` ``}``;``0``h``L``L``n``e``g``r``u``b``e``h``c" ascii
    $s3  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenODz9(\"/``*``@`` ``}``;``0``h``L``L``n``e``g``r``u``b``e``h``c" ascii
    $s4  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenODz9(\";``\\x22``k``\\x22`` ``+`` ``\\x22``z``.``\\x22`` ``+``" ascii
    $s5  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenODz9(\";``)``\\x22``h``s``c``p``j``v``u``t``l``j``/``t``e``n``" ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenODz9(\";``)``(``y``a``r``r``A`` ``w``e``n`` ``=`` ``5``y``F``n" ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenODz9(\"/``*``@`` ``}``;``}``;``e``u``n``i``t``n``o``c``{`` ``)" ascii
    $s8  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenODz9(\";``)``\\x22``h``c``d``i``g``z``z``h``/``e``m``.``i``k``" ascii
    $s9  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenODz9(\";``\\x22``k``\\x22`` ``+`` ``\\x22``z``.``\\x22`` ``+``" ascii
    $s10 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenODz9(\";``)``\\x22``h``c``d``i``g``z``z``h``/``e``m``.``i``k``" ascii
    $s11 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenODz9(\"/``*``@`` ``}``;``)``(``e``s``o``l``c``.``0``c``K``n``e" ascii
    $s12 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenODz9(\"/``*``@`` ``}``;``)``8``u``U``n``e``g``r``u``b``e``h``c" ascii
    $s13 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenODz9(\";``\\x22``X``J``j``u``b``1``g``I``x``1``y``m``N``O``l``" ascii
    $s14 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenODz9(\"\")), 1);//////////////////////////////////////////////" ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenODz9(\";``1``+``1``=``4``m``Z``S``n``e``g``r``u``b``e``h``c`` " ascii
    $s16 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenODz9(\";``0`` ``=`` ``9``j``P``S``n``e``g``r``u``b``e``h``c`` " ascii
    $s17 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenODz9(\";``)``(``y``a``r``r``A`` ``w``e``n`` ``=`` ``5``y``F``n" ascii
    $s18 = "urn cheburgenJt7[\"reverse\"]().join(\"\");} else return \"\";};" fullword ascii
    $s19 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenODz9(\";``7``a``Z``n``e``g``r``u``b``e``h``c`` ``+`` ``8``o``H" ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenODz9(\"/``*``@`` ``}``;``)``(``e``s``o``l``c``.``0``c``K``n``e" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}