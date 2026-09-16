rule sig_20161215_99967916de5adc3d4fb19515fc95f192 {
  meta:
    description = "datamaliciousorder - file 20161215_99967916de5adc3d4fb19515fc95f192.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "cef8be50b240214d98a49aab0c663f68c14bd412690e4af2673c1a9f1831c4b9"

  strings:
    $s1  = "function aAXh1(aEJb9) {eval(\"/*@cc_on var aWj8 = new Date() @*/\");aWj8[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aWj8[\"getUT" ascii
    $s2  = "function aAXh1(aEJb9) {eval(\"/*@cc_on var aWj8 = new Date() @*/\");aWj8[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aWj8[\"getUT" ascii
    $s3  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aAXh1(\";`0` `=` `4`e`N`J`a` `r`a`v\")), 1);" fullword ascii
    $s4  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aAXh1(\"/`*`@` `}`;`}`;`e`u`n`i`t`n`o`c`{` `)`e`(` `h`c`t`a`c`}`;`k" ascii
    $s5  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aAXh1(\";`1`+`1`=`3`h`N`a` `r`a`v`;`)`\\x22`t`c`e`j`b`O`m`e`t`s`y`S" ascii
    $s6  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aAXh1(\"/`*`@` `}`;`2`t`H`H`a` `n`r`u`t`e`r`;`}`;`)`8`x`R`a`(`]`\\x" ascii
    $s7  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aAXh1(\"/`*`@` `}`;`)`(`e`s`o`l`c`.`6`y`V`a`;`)`2` `,`9`w`K`U`a`(`]" ascii
    $s8  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aAXh1(\";`)`\\x22`g`i`d`d`1`/`u`r`.`o`n`i`j`y`m`.`8`8`c`i`l`o`r`c`" ascii
    $s9  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aAXh1(\"}`;`h`t`a`P`t`r`o`h`S`.`1`g`C`a` `n`r`u`t`e`r`;`)`0`g`E`a`(" ascii
    $s10 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aAXh1(\"/`*`@` `}`;`)`3`n`F`X`a`(`0`b`D`a` `n`r`u`t`e`r`;`)`(`e`s`o" ascii
    $s11 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aAXh1(\"/`*`@` `}`;`9`b`J`E`a` `n`r`u`t`e`r`;`)`\\x22`\\x22`(`]`\\x" ascii
    $s12 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aAXh1(\";`)`\\x22`P`T`T`H`L`M`X`.`2`L`M`X`S`M`\\x22`(`t`c`e`j`b`O`X" ascii
    $s13 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aAXh1(\";`)`\\x22`P`T`T`H`L`M`X`.`2`L`M`X`S`M`\\x22`(`t`c`e`j`b`O`X" ascii
    $s14 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aAXh1(\"/`*`@` `}`;`9`b`J`E`a` `n`r`u`t`e`r`;`)`\\x22`\\x22`(`]`\\x" ascii
    $s15 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aAXh1(\";`\\x22`k`\\x22` `+` `\\x22`z`.`\\x22` `+` `5`l`Q`a`=`0`g`E" ascii
    $s16 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aAXh1(\";`\\x22`k`\\x22` `+` `\\x22`z`.`\\x22` `+` `5`l`Q`a`=`0`g`E" ascii
    $s17 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aAXh1(\";`)`\\x22`g`i`d`d`1`/`u`r`.`o`n`i`j`y`m`.`8`8`c`i`l`o`r`c`" ascii
    $s18 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aAXh1(\";`)`\\x22`0`l`x`y`u`q`a`q`d`/`k`d`.`l`o`b`m`y`s`i`r`e`l`l`a" ascii
    $s19 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aAXh1(\";`)`\\x22`m`a`1`q`z`z`4`/`l`n`.`e`d`o`h`t`e`m`k`n`a`l`s`\\x" ascii
    $s20 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aAXh1(\";`)`'`/`%`P`M`E`T`%`'`(`]`'`s`g`n`i`r`t`S`t`n`e`m`n`o`r`i`v" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}