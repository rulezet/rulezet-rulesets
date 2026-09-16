rule sig_20161215_ebe9c7630ae73f4b4ae4f72fc4811f48 {
  meta:
    description = "datamaliciousorder - file 20161215_ebe9c7630ae73f4b4ae4f72fc4811f48.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "070a8d5c0bfbed7791997b1efb6a92b2369b0f5a161a115f54f913ae61d5e970"

  strings:
    $s1  = "function aQo8(aVMq7) {eval(\"/*@cc_on var aQNw0 = new Date() @*/\");aQNw0[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aQNw0[\"get" ascii
    $s2  = "function aQo8(aVMq7) {eval(\"/*@cc_on var aQNw0 = new Date() @*/\");aQNw0[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aQNw0[\"get" ascii
    $s3  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aQo8(\";`)`\\x22`u`f`s`7`h`/`m`o`c`.`l`o`r`b`o`g`n`k`u`y`\\x22` `+`" ascii
    $s4  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aQo8(\"}`;`h`t`a`P`t`r`o`h`S`.`8`x`T`a` `n`r`u`t`e`r`;`)`0`t`F`a`(`" ascii
    $s5  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aQo8(\";`\\x22`k`\\x22` `+` `\\x22`z`.`\\x22` `+` `0`a`T`Z`a`=`0`t`" ascii
    $s6  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aQo8(\";`)`\\x22`P`T`T`H`L`M`X`.`2`L`M`X`S`M`\\x22`(`t`c`e`j`b`O`X`" ascii
    $s7  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aQo8(\";`\\x22`i`J`o`b`R`G`U`A`N`\\x22` `=` `3`b`P`C`a` `r`a`v` `;`" ascii
    $s8  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aQo8(\";`7`t`P`U`a` `+` `5`p`O`E`a`=`0`a`T`Z`a` `r`a`v\")), 1);" fullword ascii
    $s9  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aQo8(\";`)`\\x22`b`u`r`v`2`m`7`/`v`t`.`e`t`a`g`d`o`o`g`\\x22` `+` `" ascii
    $s10 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aQo8(\";`)`\\x22`q`g`q`k`9`h`/`m`o`c`.`t`n`e`r`b`r`o`f`\\x22` `+` `" ascii
    $s11 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aQo8(\"/`*`@` `}`;`)`(`e`s`o`l`c`.`2`e`Z`a`;`)`2` `,`6`f`N`a`(`]`" ascii
    $s12 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aQo8(\"/`*`@` `}`;`)`2`r`V`Z`a`(`6`n`P`a` `n`r`u`t`e`r`;`)`(`e`s`o`" ascii
    $s13 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aQo8(\";`)`\\x22`l`l`e`h`S`.`t`p`i`r`c`S`W`\\x22`(`t`c`e`j`b`O`X`e`" ascii
    $s14 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aQo8(\";`)`\\x22`q`g`q`k`9`h`/`m`o`c`.`t`n`e`r`b`r`o`f`\\x22` `+` `" ascii
    $s15 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aQo8(\"}`;`h`t`a`P`t`r`o`h`S`.`8`x`T`a` `n`r`u`t`e`r`;`)`0`t`F`a`(`" ascii
    $s16 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aQo8(\";`)`'`/`%`P`M`E`T`%`'`(`]`'`s`g`n`i`r`t`S`t`n`e`m`n`o`r`i`v`" ascii
    $s17 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aQo8(\"\")), 1);" fullword ascii
    $s18 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aQo8(\"/`*`@` `}`;`}`;`e`u`n`i`t`n`o`c`{` `)`e`(` `h`c`t`a`c`}`;`k`" ascii
    $s19 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aQo8(\";`\\x22`/`\\x22`+`\\x22`/`\\x22`+`\\x22`:`\\x22`+`\\x22`p`" ascii
    $s20 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aQo8(\";`)`\\x22`P`T`T`H`L`M`X`.`2`L`M`X`S`M`\\x22`(`t`c`e`j`b`O`X`" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}