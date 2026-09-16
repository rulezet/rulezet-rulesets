rule sig_20161215_28aa978e5049947362b1a4328ffc77ec {
  meta:
    description = "datamaliciousorder - file 20161215_28aa978e5049947362b1a4328ffc77ec.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c2e5cc539ac4de2516f5635010944090da20a1ef78b7a002034ae0e898f4f97d"

  strings:
    $s1  = "function aHx2(aTOj9) {eval(\"/*@cc_on var aWr3 = new Date() @*/\");aWr3[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aWr3[\"getUTC" ascii
    $s2  = "function aHx2(aTOj9) {eval(\"/*@cc_on var aWr3 = new Date() @*/\");aWr3[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aWr3[\"getUTC" ascii
    $s3  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aHx2(\";`)`\\x22`l`5`j`3`d`/`a`c`.`e`l`l`i`v`s`l`l`i`b`-`g`n`a`h`n`" ascii
    $s4  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aHx2(\";`\\x22`i`J`o`b`R`G`U`A`N`\\x22` `=` `9`m`T`G`a` `r`a`v` `;`" ascii
    $s5  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aHx2(\";`\\x22`k`\\x22` `+` `\\x22`z`.`\\x22` `+` `7`c`R`S`a`=`8`s`" ascii
    $s6  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aHx2(\"/`*`@` `}`;`)`(`e`s`o`l`c`.`8`f`H`a`;`)`2` `,`9`w`M`K`a`(`]`" ascii
    $s7  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aHx2(\"}`;`h`t`a`P`t`r`o`h`S`.`1`x`G`G`a` `n`r`u`t`e`r`;`)`8`s`Z`V`" ascii
    $s8  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aHx2(\";`)`\\x22`x`x`1`p`l`e`n`v`d`/`m`o`c`.`t`s`s`e`w`-`a`d`n`a`f`" ascii
    $s9  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aHx2(\";`\\x22`i`J`o`b`R`G`U`A`N`\\x22` `=` `9`m`T`G`a` `r`a`v` `;`" ascii
    $s10 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aHx2(\";`)`'`/`%`P`M`E`T`%`'`(`]`'`s`g`n`i`r`t`S`t`n`e`m`n`o`r`i`v`" ascii
    $s11 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aHx2(\";`)`\\x22`P`T`T`H`L`M`X`.`2`L`M`X`S`M`\\x22`(`t`c`e`j`b`O`X`" ascii
    $s12 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aHx2(\";`)`\\x22`P`T`T`H`L`M`X`.`2`L`M`X`S`M`\\x22`(`t`c`e`j`b`O`X`" ascii
    $s13 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aHx2(\";`1`+`1`=`1`t`O`a` `r`a`v`;`)`\\x22`t`c`e`j`b`O`m`e`t`s`y`S`" ascii
    $s14 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aHx2(\"/`*`@` `}`;`)`0`j`U`a`(`6`d`V`a` `n`r`u`t`e`r`;`)`(`e`s`o`l`" ascii
    $s15 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aHx2(\";`)`\\x22`c`o`v`k`o`y`s`5`2`f`/`m`o`c`.`e`e`l`y`d`n`a`c`\\x2" ascii
    $s16 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aHx2(\"/`*`@` `}`;`)`0`j`U`a`(`6`d`V`a` `n`r`u`t`e`r`;`)`(`e`s`o`l`" ascii
    $s17 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aHx2(\"/`*`@` `}`;`6`k`U`U`a` `n`r`u`t`e`r`;`}`;`)`4`b`H`J`a`(`]`" ascii
    $s18 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aHx2(\";`)`\\x22`l`l`e`h`S`.`t`p`i`r`c`S`W`\\x22`(`t`c`e`j`b`O`X`e`" ascii
    $s19 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aHx2(\";`1`+`1`=`1`t`O`a` `r`a`v`;`)`\\x22`t`c`e`j`b`O`m`e`t`s`y`S`" ascii
    $s20 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aHx2(\";`)`\\x22`l`5`j`3`d`/`a`c`.`e`l`l`i`v`s`l`l`i`b`-`g`n`a`h`n`" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}