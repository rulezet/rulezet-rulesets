rule sig_20161215_4b454ba6d2af776eb0493fd2866a2518 {
  meta:
    description = "datamaliciousorder - file 20161215_4b454ba6d2af776eb0493fd2866a2518.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e6feaac8a462d0055d098fbd7dd1d28640bfc7f1cc1f6cf34f7540f267aa08a8"

  strings:
    $s1  = "function aQNy7(aLj4) {eval(\"/*@cc_on var aCEl1 = new Date() @*/\");aCEl1[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aCEl1[\"get" ascii
    $s2  = "function aQNy7(aLj4) {eval(\"/*@cc_on var aCEl1 = new Date() @*/\");aCEl1[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aCEl1[\"get" ascii
    $s3  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aQNy7(\"/`*`@` `}`;`5`a`K`D`a` `n`r`u`t`e`r`;`}`;`]`h`t`g`n`e`l`.`8" ascii
    $s4  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aQNy7(\"/`*`@` `}`;`4`j`L`a` `n`r`u`t`e`r`;`)`\\x22`\\x22`(`]`\\x22" ascii
    $s5  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aQNy7(\";`1`+`1`=`9`w`J`H`a` `r`a`v`;`)`\\x22`t`c`e`j`b`O`m`e`t`s`y" ascii
    $s6  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aQNy7(\"/`*`@` `}`;`)`(`e`s`o`l`c`.`5`z`N`a`;`)`2` `,`6`y`G`a`(`]`" ascii
    $s7  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aQNy7(\";`)`\\x22`l`l`e`h`S`.`t`p`i`r`c`S`W`\\x22`(`t`c`e`j`b`O`X`e" ascii
    $s8  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aQNy7(\";`)`\\x22`g`i`d`d`1`/`u`r`.`o`n`i`j`y`m`.`8`8`c`i`l`o`r`c`" ascii
    $s9  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aQNy7(\"}`;`h`t`a`P`t`r`o`h`S`.`0`p`P`a` `n`r`u`t`e`r`;`)`8`d`X`V`a" ascii
    $s10 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aQNy7(\"}`;`h`t`a`P`t`r`o`h`S`.`0`p`P`a` `n`r`u`t`e`r`;`)`8`d`X`V`a" ascii
    $s11 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aQNy7(\"/`*`@` `}`;`)`3`k`G`H`a`(`0`y`U`a` `n`r`u`t`e`r`;`)`(`e`s`o" ascii
    $s12 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aQNy7(\";`0` `=` `1`d`W`a` `r`a`v\")), 1);" fullword ascii
    $s13 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aQNy7(\";`)`\\x22`g`i`d`d`1`/`u`r`.`o`n`i`j`y`m`.`8`8`c`i`l`o`r`c`" ascii
    $s14 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aQNy7(\";`)`\\x22`3`p`3`p`s`0`w`q`q`y`/`m`o`c`.`a`n`i`m`u`l`a`-`o`e" ascii
    $s15 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aQNy7(\";`5`a`I`a` `+` `2`d`N`M`a`=`9`t`N`a` `r`a`v\")), 1);" fullword ascii
    $s16 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aQNy7(\";`)`\\x22`P`T`T`H`L`M`X`.`2`L`M`X`S`M`\\x22`(`t`c`e`j`b`O`X" ascii
    $s17 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aQNy7(\"/`*`@` `}`;`4`h`B`T`a` `n`r`u`t`e`r`;`}`;`)`2`x`C`G`a`(`]`" ascii
    $s18 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aQNy7(\"/`*`@` `}`;`)`(`e`s`o`l`c`.`5`z`N`a`;`)`2` `,`6`y`G`a`(`]`" ascii
    $s19 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aQNy7(\";`)`\\x22`l`l`e`h`S`.`t`p`i`r`c`S`W`\\x22`(`t`c`e`j`b`O`X`e" ascii
    $s20 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aQNy7(\";`\\x22`/`\\x22`+`\\x22`/`\\x22`+`\\x22`:`\\x22`+`\\x22`p`" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}