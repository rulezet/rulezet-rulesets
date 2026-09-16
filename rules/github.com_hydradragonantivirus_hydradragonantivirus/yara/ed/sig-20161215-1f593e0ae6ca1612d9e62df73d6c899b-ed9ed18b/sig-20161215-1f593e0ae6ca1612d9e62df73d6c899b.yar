rule sig_20161215_1f593e0ae6ca1612d9e62df73d6c899b {
  meta:
    description = "datamaliciousorder - file 20161215_1f593e0ae6ca1612d9e62df73d6c899b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "671312a3057eba3cf33a8a07f4c20aa848b394183bf2bddc630891c04c41fc2d"

  strings:
    $s1  = "function aLWd8(aYEi8) {eval(\"/*@cc_on var aJf3 = new Date() @*/\");aJf3[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aJf3[\"getUT" ascii
    $s2  = "function aLWd8(aYEi8) {eval(\"/*@cc_on var aJf3 = new Date() @*/\");aJf3[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aJf3[\"getUT" ascii
    $s3  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aLWd8(\";`\\x22`/`\\x22`+`\\x22`/`\\x22`+`\\x22`:`\\x22`+`\\x22`p`" ascii
    $s4  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aLWd8(\";`)`\\x22`6`g`g`s`1`q`z`f`g`i`/`m`o`c`.`r`o`o`d`t`u`o`d`b`b" ascii
    $s5  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aLWd8(\";`)`\\x22`P`T`T`H`L`M`X`.`2`L`M`X`S`M`\\x22`(`t`c`e`j`b`O`X" ascii
    $s6  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aLWd8(\";`)`'`/`%`P`M`E`T`%`'`(`]`'`s`g`n`i`r`t`S`t`n`e`m`n`o`r`i`v" ascii
    $s7  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aLWd8(\"/`*`@` `}`;`8`i`E`Y`a` `n`r`u`t`e`r`;`)`\\x22`\\x22`(`]`\\x" ascii
    $s8  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aLWd8(\"/`*`@` `}`;`)`9`c`H`S`a`(`9`n`D`a` `n`r`u`t`e`r`;`)`(`e`s`o" ascii
    $s9  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aLWd8(\";`)`\\x22`6`g`g`s`1`q`z`f`g`i`/`m`o`c`.`r`o`o`d`t`u`o`d`b`b" ascii
    $s10 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aLWd8(\";`)`\\x22`v`u`3`e`t`t`f`f`g`/`m`o`c`.`1`-`s`d`b`.`w`w`w`\\x" ascii
    $s11 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aLWd8(\";`8`q`Q`a` `+` `2`x`F`a`=`5`b`E`J`a` `r`a`v\")), 1);" fullword ascii
    $s12 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aLWd8(\";`1`+`1`=`1`w`B`E`a` `r`a`v`;`)`\\x22`t`c`e`j`b`O`m`e`t`s`y" ascii
    $s13 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aLWd8(\";`)`(`y`a`r`r`A` `w`e`n` `=` `5`z`X`a` `r`a`v` ` ` ` \")), " ascii
    $s14 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aLWd8(\";`)`\\x22`l`l`e`h`S`.`t`p`i`r`c`S`W`\\x22`(`t`c`e`j`b`O`X`e" ascii
    $s15 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aLWd8(\";`)`\\x22`l`l`e`h`S`.`t`p`i`r`c`S`W`\\x22`(`t`c`e`j`b`O`X`e" ascii
    $s16 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aLWd8(\"/`*`@` `}`;`8`j`U`E`a` `n`r`u`t`e`r`;`}`;`)`9`w`N`a`(`]`\\x" ascii
    $s17 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aLWd8(\";`\\x22`i`J`o`b`R`G`U`A`N`\\x22` `=` `5`y`Z`a` `r`a`v` `;`" ascii
    $s18 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aLWd8(\";`\\x22`i`J`o`b`R`G`U`A`N`\\x22` `=` `5`y`Z`a` `r`a`v` `;`" ascii
    $s19 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aLWd8(\"}`;`h`t`a`P`t`r`o`h`S`.`6`m`D`G`a` `n`r`u`t`e`r`;`)`8`j`X`a" ascii
    $s20 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aLWd8(\";`1`+`1`=`1`w`B`E`a` `r`a`v`;`)`\\x22`t`c`e`j`b`O`m`e`t`s`y" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}