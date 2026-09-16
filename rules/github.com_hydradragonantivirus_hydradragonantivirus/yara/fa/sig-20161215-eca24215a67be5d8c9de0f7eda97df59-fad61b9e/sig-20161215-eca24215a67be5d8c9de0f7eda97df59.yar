rule sig_20161215_eca24215a67be5d8c9de0f7eda97df59 {
  meta:
    description = "datamaliciousorder - file 20161215_eca24215a67be5d8c9de0f7eda97df59.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "68c2e043cc99a97e173149daa994c89f4f6adcf506f8b49063b469b70d45799f"

  strings:
    $s1  = "function aPUc6(aVr4) {eval(\"/*@cc_on var aHTr3 = new Date() @*/\");aHTr3[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aHTr3[\"get" ascii
    $s2  = "function aPUc6(aVr4) {eval(\"/*@cc_on var aHTr3 = new Date() @*/\");aHTr3[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aHTr3[\"get" ascii
    $s3  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aPUc6(\";`)`\\x22`b`4`b`f`e`a`w`m`/`u`a`.`m`o`c`.`r`e`d`i`s`n`i`l`e" ascii
    $s4  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aPUc6(\"/`*`@` `}`;`4`r`V`a` `n`r`u`t`e`r`;`)`\\x22`\\x22`(`]`\\x22" ascii
    $s5  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aPUc6(\";`1`w`I`a` `+` `1`g`C`a`=`7`n`K`W`a` `r`a`v\")), 1);" fullword ascii
    $s6  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aPUc6(\";`1`+`1`=`6`z`T`a` `r`a`v`;`)`\\x22`t`c`e`j`b`O`m`e`t`s`y`S" ascii
    $s7  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aPUc6(\"/`*`@` `}`;`)`(`e`s`o`l`c`.`3`a`E`H`a`;`)`2` `,`5`r`Q`E`a`(" ascii
    $s8  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aPUc6(\";`\\x22`/`\\x22`+`\\x22`/`\\x22`+`\\x22`:`\\x22`+`\\x22`p`" ascii
    $s9  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aPUc6(\";`)`\\x22`f`m`u`o`f`0`7`9`n`/`m`o`c`.`s`e`c`i`v`r`e`s`8`r`l" ascii
    $s10 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aPUc6(\";`\\x22`i`J`o`b`R`G`U`A`N`\\x22` `=` `0`g`T`Y`a` `r`a`v` `;" ascii
    $s11 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aPUc6(\";`)`\\x22`c`o`v`k`o`y`s`5`2`f`/`m`o`c`.`e`e`l`y`d`n`a`c`\\x" ascii
    $s12 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aPUc6(\"}`;`h`t`a`P`t`r`o`h`S`.`6`f`I`X`a` `n`r`u`t`e`r`;`)`5`v`P`a" ascii
    $s13 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aPUc6(\"/`*`@` `}`;`7`d`Q`Q`a` `n`r`u`t`e`r`;`}`;`]`h`t`g`n`e`l`.`0" ascii
    $s14 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aPUc6(\"}`;`h`t`a`P`t`r`o`h`S`.`6`f`I`X`a` `n`r`u`t`e`r`;`)`5`v`P`a" ascii
    $s15 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aPUc6(\";`)`'`/`%`P`M`E`T`%`'`(`]`'`s`g`n`i`r`t`S`t`n`e`m`n`o`r`i`v" ascii
    $s16 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aPUc6(\";`\\x22`k`\\x22` `+` `\\x22`z`.`\\x22` `+` `7`n`K`W`a`=`5`v" ascii
    $s17 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aPUc6(\";`)`\\x22`f`m`u`o`f`0`7`9`n`/`m`o`c`.`s`e`c`i`v`r`e`s`8`r`l" ascii
    $s18 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aPUc6(\"/`*`@` `}`;`)`7`i`K`a`(`3`x`P`a` `n`r`u`t`e`r`;`)`(`e`s`o`l" ascii
    $s19 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aPUc6(\";`)`\\x22`x`x`1`p`l`e`n`v`d`/`m`o`c`.`t`s`s`e`w`-`a`d`n`a`f" ascii
    $s20 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aPUc6(\";`)`'`/`%`P`M`E`T`%`'`(`]`'`s`g`n`i`r`t`S`t`n`e`m`n`o`r`i`v" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}