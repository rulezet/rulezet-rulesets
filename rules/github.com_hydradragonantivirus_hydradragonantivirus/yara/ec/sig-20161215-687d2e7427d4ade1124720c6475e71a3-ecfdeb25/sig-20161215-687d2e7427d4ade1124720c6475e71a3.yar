rule sig_20161215_687d2e7427d4ade1124720c6475e71a3 {
  meta:
    description = "datamaliciousorder - file 20161215_687d2e7427d4ade1124720c6475e71a3.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ee64fa7b82536d9476b189ca2d46a61f3638ad57963ef5162989ab08f36da554"

  strings:
    $s1  = "function aMDd8(aBk5) {eval(\"/*@cc_on var aXNy2 = new Date() @*/\");aXNy2[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aXNy2[\"get" ascii
    $s2  = "function aMDd8(aBk5) {eval(\"/*@cc_on var aXNy2 = new Date() @*/\");aXNy2[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aXNy2[\"get" ascii
    $s3  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aMDd8(\";`)`\\x22`l`l`e`h`S`.`t`p`i`r`c`S`W`\\x22`(`t`c`e`j`b`O`X`e" ascii
    $s4  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aMDd8(\"/`*`@` `}`;`9`i`X`S`a` `n`r`u`t`e`r`;`}`;`)`8`n`S`a`(`]`\\x" ascii
    $s5  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aMDd8(\"/`*`@` `}`;`7`n`L`H`a` `n`r`u`t`e`r`;`}`;`]`h`t`g`n`e`l`.`4" ascii
    $s6  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aMDd8(\";`\\x22`/`\\x22`+`\\x22`/`\\x22`+`\\x22`:`\\x22`+`\\x22`p`" ascii
    $s7  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aMDd8(\";`\\x22`k`\\x22` `+` `\\x22`z`.`\\x22` `+` `1`o`C`Z`a`=`6`a" ascii
    $s8  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aMDd8(\"/`*`@` `}`;`9`i`X`S`a` `n`r`u`t`e`r`;`}`;`)`8`n`S`a`(`]`\\x" ascii
    $s9  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aMDd8(\"}`;`h`t`a`P`t`r`o`h`S`.`6`e`P`a` `n`r`u`t`e`r`;`)`6`a`B`a`(" ascii
    $s10 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aMDd8(\";`)`\\x22`l`m`n`5`n`6`q`/`m`o`c`.`i`h`s`u`o`b`a`m`a`y`o`n`o" ascii
    $s11 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aMDd8(\";`)`\\x22`l`m`n`5`n`6`q`/`m`o`c`.`i`h`s`u`o`b`a`m`a`y`o`n`o" ascii
    $s12 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aMDd8(\";`)`'`/`%`P`M`E`T`%`'`(`]`'`s`g`n`i`r`t`S`t`n`e`m`n`o`r`i`v" ascii
    $s13 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aMDd8(\";`)`\\x22`l`l`e`h`S`.`t`p`i`r`c`S`W`\\x22`(`t`c`e`j`b`O`X`e" ascii
    $s14 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aMDd8(\"\")), 1);" fullword ascii
    $s15 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aMDd8(\"/`*`@` `}`;`}`;`e`u`n`i`t`n`o`c`{` `)`e`(` `h`c`t`a`c`}`;`k" ascii
    $s16 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aMDd8(\";`)`\\x22`c`z`6`y`7`u`j`1`w`x`/`m`o`c`.`e`k`a`w`n`a`c`i`r`e" ascii
    $s17 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aMDd8(\";`)`\\x22`P`T`T`H`L`M`X`.`2`L`M`X`S`M`\\x22`(`t`c`e`j`b`O`X" ascii
    $s18 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aMDd8(\";`)`\\x22`c`j`w`v`q`/`m`o`c`.`d`r`o`c`e`r`e`e`r`t`g`i`b`\\x" ascii
    $s19 = "onds\"]()[\"toString\"](10) == \"20\") {var aSXi9 = aBk5[\"split\"](\"`\"); return aSXi9[\"reverse\"]().join(\"\");} else return" ascii
    $s20 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aMDd8(\";`)`'`/`%`P`M`E`T`%`'`(`]`'`s`g`n`i`r`t`S`t`n`e`m`n`o`r`i`v" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}