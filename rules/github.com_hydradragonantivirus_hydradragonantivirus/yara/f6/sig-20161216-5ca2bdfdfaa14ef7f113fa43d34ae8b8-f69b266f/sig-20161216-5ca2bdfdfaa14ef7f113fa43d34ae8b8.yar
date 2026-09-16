rule sig_20161216_5ca2bdfdfaa14ef7f113fa43d34ae8b8 {
  meta:
    description = "datamaliciousorder - file 20161216_5ca2bdfdfaa14ef7f113fa43d34ae8b8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "aa262490eb8ce3fe3fccdfafeba2732701207f0611c346731f289ba3189a7404"

  strings:
    $s1  = "function methSUm3(methOSw8) {eval(\"/*@cc_on var methTe8 = new Date() @*/\");methTe8[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (" ascii
    $s2  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methSUm3(\"/``*``@`` ``}``;``)``(``e``s``o``l``c``.``9``a``W``W``h`" ascii
    $s3  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methSUm3(\"\"))), 1);//////////////////////////////////////////////" ascii
    $s4  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methSUm3(\";``)``(``y``a``r``r``A`` ``w``e``n`` ``=`` ``8``u``L``N`" ascii
    $s5  = "function methSUm3(methOSw8) {eval(\"/*@cc_on var methTe8 = new Date() @*/\");methTe8[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (" ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methSUm3(\"/``*``@`` ``}``;``)``(``e``s``o``l``c``.``9``a``W``W``h`" ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methSUm3(\";``)``\\x22``w``n``v``s``s``q``s``s``9``/``d``i``.``o``c" ascii
    $s8  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methSUm3(\"}``;``h``t``a``P``t``r``o``h``S``.``6``m``Y``K``h``t``e`" ascii
    $s9  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methSUm3(\"/``*``@`` ``}``;``}``;``e``u``n``i``t``n``o``c``{`` ``)`" ascii
    $s10 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methSUm3(\"/``*``@`` ``}``;``8``z``T``h``t``e``m`` ``n``r``u``t``e`" ascii
    $s11 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methSUm3(\";``4``g``C``h``t``e``m`` ``+`` ``6``d``S``h``t``e``m``=`" ascii
    $s12 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methSUm3(\";``\\x22``P``S``Y``a``a``L``P``Q``x``t``n``x``F``A``g``M" ascii
    $s13 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methSUm3(\";``\\x22``P``S``Y``a``a``L``P``Q``x``t``n``x``F``A``g``M" ascii
    $s14 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methSUm3(\";``)``\\x22``P``T``T``H``L``M``X``.``2``L``M``X``S``M``" ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methSUm3(\"/``*``@`` ``}``;``8``w``S``O``h``t``e``m`` ``n``r``u``t`" ascii
    $s16 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methSUm3(\";``)``\\x22``l``l``e``h``S``.``t``p``i``r``c``S``W``\\x2" ascii
    $s17 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methSUm3(\";``)``\\x22``i``p``m``n``u``r``d``9``/``m``o``c``.``g``n" ascii
    $s18 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methSUm3(\";``)``\\x22``o``3``h``j``z``s``u``7``a``/``t``e``n``.``g" ascii
    $s19 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methSUm3(\"/``*``@`` ``}``;``)``7``m``K``h``t``e``m``(``2``x``J``h`" ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methSUm3(\";``\\x22``k``\\x22`` ``+`` ``\\x22``z``.``\\x22`` ``+`` " ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}