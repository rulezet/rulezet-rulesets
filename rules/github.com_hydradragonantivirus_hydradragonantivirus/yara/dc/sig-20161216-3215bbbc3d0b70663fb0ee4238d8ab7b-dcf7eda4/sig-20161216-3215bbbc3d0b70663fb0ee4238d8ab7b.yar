rule sig_20161216_3215bbbc3d0b70663fb0ee4238d8ab7b {
  meta:
    description = "datamaliciousorder - file 20161216_3215bbbc3d0b70663fb0ee4238d8ab7b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8f6869e63ec8cca8c39cc1886a92e60260408782b7543bfa3810447222d33885"

  strings:
    $s1  = "function cheburgenYDa9(cheburgenAQu5) {eval(\"/*@cc_on var cheburgenTo9 = new Date() @*/\");cheburgenTo9[\"setUTC\"+\"Seconds\"]" ascii
    $s2  = "\"20\");if (cheburgenTo9[\"getUTCMilliseconds\"]()[\"toString\"](10) == \"20\") {var cheburgenZy2 = cheburgenAQu5[\"split\"](\"`" ascii
    $s3  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenYDa9(\"}``;``h``t``a``P``t``r``o``h``S``.``4``u``K``H``n``e``g" ascii
    $s4  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenYDa9(\";``)``\\x22``P``T``T``H``L``M``X``.``2``L``M``X``S``M``" ascii
    $s5  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenYDa9(\"\")), 1);//////////////////////////////////////////////" ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenYDa9(\"/``*``@`` ``}``;``)``(``e``s``o``l``c``.``0``e``U``T``n" ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenYDa9(\";``)``\\x22``g``o``7``w``u``z``e``z``a``y``/``e``s``.``" ascii
    $s8  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenYDa9(\";``\\x22``X``J``j``u``b``1``g``I``x``1``y``m``N``O``l``" ascii
    $s9  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenYDa9(\"}``;``h``t``a``P``t``r``o``h``S``.``4``u``K``H``n``e``g" ascii
    $s10 = "function cheburgenYDa9(cheburgenAQu5) {eval(\"/*@cc_on var cheburgenTo9 = new Date() @*/\");cheburgenTo9[\"setUTC\"+\"Seconds\"]" ascii
    $s11 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenYDa9(\";``)``\\x22``o``7``j``c``y``/``z``t``.``o``c``.``s``r``" ascii
    $s12 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenYDa9(\"/``*``@`` ``}``;``4``e``T``P``n``e``g``r``u``b``e``h``c" ascii
    $s13 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenYDa9(\"\")), 1);//////////////////////////////////////////////" ascii
    $s14 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenYDa9(\";``\\x22``k``\\x22`` ``+`` ``\\x22``z``.``\\x22`` ``+``" ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenYDa9(\";``)``'``/``%``P``M``E``T``%``'``(``]``'``s``g``n``i``r" ascii
    $s16 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenYDa9(\";``)``\\x22``g``o``7``w``u``z``e``z``a``y``/``e``s``.``" ascii
    $s17 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenYDa9(\"/``*``@`` ``}``;``)``(``e``s``o``l``c``.``0``e``U``T``n" ascii
    $s18 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenYDa9(\";``)``\\x22``l``l``e``h``S``.``t``p``i``r``c``S``W``\\x" ascii
    $s19 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenYDa9(\";``\\x22``k``\\x22`` ``+`` ``\\x22``z``.``\\x22`` ``+``" ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenYDa9(\"/``*``@`` ``}``;``2``y``Z``n``e``g``r``u``b``e``h``c`` " ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}