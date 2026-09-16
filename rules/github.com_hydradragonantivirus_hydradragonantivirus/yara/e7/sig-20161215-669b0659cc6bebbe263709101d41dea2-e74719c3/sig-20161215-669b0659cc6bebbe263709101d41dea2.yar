rule sig_20161215_669b0659cc6bebbe263709101d41dea2 {
  meta:
    description = "datamaliciousorder - file 20161215_669b0659cc6bebbe263709101d41dea2.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f17650748a071ebbc1bd918f512e2aa8fd092e5c2ea30550b4bc036408ad2aef"

  strings:
    $s1  = "function cheburgenOj7(cheburgenQSp6) {eval(\"/*@cc_on var cheburgenQXh1 = new Date() @*/\");cheburgenQXh1[\"setUTC\"+\"Seconds\"" ascii
    $s2  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenOj7(\"/``*``@`` ``}``;``8``l``X``C``n``e``g``r``u``b``e``h``c`" ascii
    $s3  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenOj7(\";``)``\\x22``o``7``f``a``n``h``p``p``v``c``/``m``o``c``." ascii
    $s4  = "urn cheburgenYYc9[\"reverse\"]().join(\"\");} else return \"\";};" fullword ascii
    $s5  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenOj7(\";``)``(``y``a``r``r``A`` ``w``e``n`` ``=`` ``9``k``F``n`" ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenOj7(\"/``*``@`` ``}``;``)``(``e``s``o``l``c``.``4``d``R``n``e`" ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenOj7(\";``1``b``S``n``e``g``r``u``b``e``h``c`` ``+`` ``0``i``X`" ascii
    $s8  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenOj7(\";``)``\\x22``x``i``u``s``c``/``m``o``c``.``u``o``g``i``a" ascii
    $s9  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenOj7(\";``)``(``y``a``r``r``A`` ``w``e``n`` ``=`` ``9``k``F``n`" ascii
    $s10 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenOj7(\";``\\x22``X``J``j``u``b``1``g``I``x``1``y``m``N``O``l``" ascii
    $s11 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenOj7(\";``\\x22``/``\\x22``+``\\x22``/``\\x22``+``\\x22``:``\\x" ascii
    $s12 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenOj7(\"/``*``@`` ``}``;``)``(``e``s``o``l``c``.``4``d``R``n``e`" ascii
    $s13 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenOj7(\"/``*``@`` ``}``;``6``p``S``Q``n``e``g``r``u``b``e``h``c`" ascii
    $s14 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenOj7(\";``1``+``1``=``3``s``E``X``n``e``g``r``u``b``e``h``c`` `" ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenOj7(\"/``*``@`` ``}``;``9``c``Y``Y``n``e``g``r``u``b``e``h``c`" ascii
    $s16 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenOj7(\";``\\x22``k``\\x22`` ``+`` ``\\x22``z``.``\\x22`` ``+`` " ascii
    $s17 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenOj7(\";``\\x22``X``J``j``u``b``1``g``I``x``1``y``m``N``O``l``" ascii
    $s18 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenOj7(\";``)``'``/``%``P``M``E``T``%``'``(``]``'``s``g``n``i``r`" ascii
    $s19 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenOj7(\";``)``'``/``%``P``M``E``T``%``'``(``]``'``s``g``n``i``r`" ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenOj7(\"/``*``@`` ``}``;``}``;``e``u``n``i``t``n``o``c``{`` ``)`" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}