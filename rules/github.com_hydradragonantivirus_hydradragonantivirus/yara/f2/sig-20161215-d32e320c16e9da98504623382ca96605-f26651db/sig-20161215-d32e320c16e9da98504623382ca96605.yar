rule sig_20161215_d32e320c16e9da98504623382ca96605 {
  meta:
    description = "datamaliciousorder - file 20161215_d32e320c16e9da98504623382ca96605.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "cc36fb92550406385d84d02382b9cfe7ef2e167498fe032671a050ac079557b7"

  strings:
    $s1  = "function cheburgenRKc3(cheburgenYg7) {eval(\"/*@cc_on var cheburgenLg8 = new Date() @*/\");cheburgenLg8[\"setUTC\"+\"Seconds\"](" ascii
    $s2  = "20\");if (cheburgenLg8[\"getUTCMilliseconds\"]()[\"toString\"](10) == \"20\") {var cheburgenGPs0 = cheburgenYg7[\"split\"](\"``" ascii
    $s3  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenRKc3(\";``)``\\x22``b``8``d``d``d``q``p``n``/``e``c``a``s``l``" ascii
    $s4  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenRKc3(\";``)``\\x22``\\x22`` ``+`` ``4``a``E``F``n``e``g``r``u`" ascii
    $s5  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenRKc3(\";``\\x22``X``J``j``u``b``1``g``I``x``1``y``m``N``O``l``" ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenRKc3(\";``\\x22``/``\\x22``+``\\x22``/``\\x22``+``\\x22``:``" ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenRKc3(\";``)``\\x22``i``t``v``j``a``7``a``b``l``/``m``o``c``.``" ascii
    $s8  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenRKc3(\"/``*``@`` ``}``;``)``6``s``U``S``n``e``g``r``u``b``e``h" ascii
    $s9  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenRKc3(\"/``*``@`` ``}``;``1``a``D``n``e``g``r``u``b``e``h``c`` " ascii
    $s10 = "cheburgenGPs0[\"reverse\"]().join(\"\");} else return \"\";};" fullword ascii
    $s11 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenRKc3(\";``)``\\x22``p``e``t``f``1``e``8``u``o``/``t``i``.``l``" ascii
    $s12 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenRKc3(\";``8``p``I``Q``n``e``g``r``u``b``e``h``c`` ``+`` ``3``f" ascii
    $s13 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenRKc3(\";``0`` ``=`` ``8``c``L``n``e``g``r``u``b``e``h``c`` ``r" ascii
    $s14 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenRKc3(\";``)``\\x22``i``t``v``j``a``7``a``b``l``/``m``o``c``.``" ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenRKc3(\"/``*``@`` ``}``;``)``(``e``s``o``l``c``.``7``u``F``n``e" ascii
    $s16 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenRKc3(\";``)``(``y``a``r``r``A`` ``w``e``n`` ``=`` ``7``q``W``J" ascii
    $s17 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenRKc3(\";``)``\\x22``b``8``d``d``d``q``p``n``/``e``c``a``s``l``" ascii
    $s18 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenRKc3(\"}``;``h``t``a``P``t``r``o``h``S``.``4``b``O``H``n``e``g" ascii
    $s19 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenRKc3(\"/``*``@`` ``}``;``}``;``e``u``n``i``t``n``o``c``{`` ``)" ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenRKc3(\";``)``\\x22``l``l``e``h``S``.``t``p``i``r``c``S``W``\\x" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}