rule _20161216_819b1651859b8fffbab6802414fa42d8_20161216_c90a443fe4c9_2587 {
  meta:
    description = "datamaliciousorder - from files 20161216_819b1651859b8fffbab6802414fa42d8.js, 20161216_c90a443fe4c9c30ca59fe3b79c0b6672.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b8883330fa3c29804d456ad45196bac077630fb80ade1f1f8dae6f1c9c410b70"
    hash2       = "db60b5de8a50d6508933e4d452b1df26c60596e938b7827739e6edb196b4b044"

  strings:
    $s1 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methEq0(\";``\\x22``P``S``Y``a``a``L``P``Q``x``t``n``x``F``A``g``M`" ascii
    $s2 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methEq0(\"\"))), 1);///////////////////////////////////////////////" ascii
    $s3 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methEq0(\";``)``\\x22``P``T``T``H``L``M``X``.``2``L``M``X``S``M``" ascii
    $s4 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methEq0(\";``\\x22``/``\\x22``+``\\x22``/``\\x22``+``\\x22``:``\\x2" ascii
    $s5 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methEq0(\";``)``'``/``%``P``M``E``T``%``'``(``]``'``s``g``n``i``r``" ascii
    $s6 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methEq0(\";``)``\\x22``l``l``e``h``S``.``t``p``i``r``c``S``W``\\x22" ascii
    $s7 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methEq0(\"/``*``@`` ``}``;``}``;``e``u``n``i``t``n``o``c``{`` ``)``" ascii
    $s8 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methEq0(\"\"))), 1);///////////////////////////////////////////////" ascii

  condition:
    (uint16(0) == 0x7566 and (all of them)
    ) or (all of them)
}