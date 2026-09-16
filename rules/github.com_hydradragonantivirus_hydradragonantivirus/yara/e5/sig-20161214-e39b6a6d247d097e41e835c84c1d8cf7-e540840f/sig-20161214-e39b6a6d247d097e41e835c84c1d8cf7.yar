rule sig_20161214_e39b6a6d247d097e41e835c84c1d8cf7 {
  meta:
    description = "datamaliciousorder - file 20161214_e39b6a6d247d097e41e835c84c1d8cf7.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "972b1b35ad599c2d1977180a24696e98b206788757f98105076621a6ecd5b8d8"

  strings:
    $s1  = "function aSZo6(aNz7) {eval(\"/*@cc_on var aRd9 = new Date() @*/\");aRd9[\"setUTCSeconds\"](\"0\", \"20\");if (aRd9.getUTCMillise" ascii
    $s2  = "function aSZo6(aNz7) {eval(\"/*@cc_on var aRd9 = new Date() @*/\");aRd9[\"setUTCSeconds\"](\"0\", \"20\");if (aRd9.getUTCMillise" ascii
    $s3  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aSZo6(\";`)`'`/`%`P`M`E`T`%`'`(`]`'`s`g`n`i`r`t`S`t`n`e`m`n`o`r`i`v" ascii
    $s4  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aSZo6(\"/`*`@` `}`;`)`8`o`N`a`(`0`e`G`H`a` `n`r`u`t`e`r`;`)`(`e`s`o" ascii
    $s5  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aSZo6(\"/`*`@` `}`;`3`p`C`K`a` `n`r`u`t`e`r`;`}`;`]`h`t`g`n`e`l`.`5" ascii
    $s6  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aSZo6(\";`)`(`y`a`r`r`A` `w`e`n` `=` `9`b`M`a` `r`a`v` ` ` ` \")), " ascii
    $s7  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aSZo6(\";`)`\\x22`f`g`s`i`n`b`7`/`z`c`.`k`a`l`m`u`h`.`4`6`n`a`m`o`r" ascii
    $s8  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aSZo6(\"/`*`@` `}`;`}`;`e`u`n`i`t`n`o`c`{` `)`e`(` `h`c`t`a`c`}`;`k" ascii
    $s9  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aSZo6(\";`)`\\x22`P`T`T`H`L`M`X`.`2`L`M`X`S`M`\\x22`(`t`c`e`j`b`O`X" ascii
    $s10 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aSZo6(\"/`*`@` `}`;`7`k`E`a` `n`r`u`t`e`r`;`}`;`)`9`p`Z`A`a`(`]`\\x" ascii
    $s11 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aSZo6(\";`\\x22`k`\\x22` `+` `\\x22`z`.`\\x22` `+` `4`f`N`a`=`4`g`I" ascii
    $s12 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aSZo6(\";`)`\\x22`n`g`h`b`5`k`/`m`o`c`.`8`6`6`0`\\x22` `+` `5`k`S`L" ascii
    $s13 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aSZo6(\"/`*`@` `}`;`3`p`C`K`a` `n`r`u`t`e`r`;`}`;`]`h`t`g`n`e`l`.`5" ascii
    $s14 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aSZo6(\";`\\x22`/`\\x22`+`\\x22`/`\\x22`+`\\x22`:`\\x22`+`\\x22`p`" ascii
    $s15 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aSZo6(\"/`*`@` `}`;`)`(`e`s`o`l`c`.`0`w`J`a`;`)`2` `,`0`o`T`B`a`(`]" ascii
    $s16 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aSZo6(\"/`*`@` `}`;`7`k`E`a` `n`r`u`t`e`r`;`}`;`)`9`p`Z`A`a`(`]`\\x" ascii
    $s17 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aSZo6(\";`)`\\x22`f`s`a`j`v`d`6`/`m`o`c`.`h`n`i`d`y`m`e`m`o`h`n`i`v" ascii
    $s18 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aSZo6(\";`)`\\x22`e`e`u`n`p`t`e`a`e`f`/`m`o`c`.`o`y`u`o`s`u`o`s`.`t" ascii
    $s19 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aSZo6(\"}`;`h`t`a`P`t`r`o`h`S`.`8`p`V`a` `n`r`u`t`e`r`;`)`4`g`I`a`(" ascii
    $s20 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aSZo6(\";`)`'`/`%`P`M`E`T`%`'`(`]`'`s`g`n`i`r`t`S`t`n`e`m`n`o`r`i`v" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}