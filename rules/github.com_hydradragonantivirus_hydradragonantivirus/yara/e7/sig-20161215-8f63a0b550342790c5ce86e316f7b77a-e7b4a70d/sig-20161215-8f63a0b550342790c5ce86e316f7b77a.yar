rule sig_20161215_8f63a0b550342790c5ce86e316f7b77a {
  meta:
    description = "datamaliciousorder - file 20161215_8f63a0b550342790c5ce86e316f7b77a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "82f739aad87a2b1b9b4eaa261f11b74f4bee2653a2a97d1ad0585ae3710c385b"

  strings:
    $s1  = "function aSh7(aDf8) {eval(\"/*@cc_on var aEPo2 = new Date() @*/\");aEPo2[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aEPo2[\"getU" ascii
    $s2  = "function aSh7(aDf8) {eval(\"/*@cc_on var aEPo2 = new Date() @*/\");aEPo2[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aEPo2[\"getU" ascii
    $s3  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aSh7(\";`)`\\x22`v`u`3`e`t`t`f`f`g`/`m`o`c`.`1`-`s`d`b`.`w`w`w`\\x2" ascii
    $s4  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aSh7(\"}`;`h`t`a`P`t`r`o`h`S`.`0`l`H`W`a` `n`r`u`t`e`r`;`)`2`g`I`a`" ascii
    $s5  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aSh7(\";`\\x22`k`\\x22` `+` `\\x22`z`.`\\x22` `+` `2`f`N`Q`a`=`2`g`" ascii
    $s6  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aSh7(\"/`*`@` `}`;`8`e`J`a` `n`r`u`t`e`r`;`}`;`]`h`t`g`n`e`l`.`3`c`" ascii
    $s7  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aSh7(\"/`*`@` `}`;`)`(`e`s`o`l`c`.`8`e`L`K`a`;`)`2` `,`9`s`F`C`a`(`" ascii
    $s8  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aSh7(\";`)`\\x22`l`l`e`h`S`.`t`p`i`r`c`S`W`\\x22`(`t`c`e`j`b`O`X`e`" ascii
    $s9  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aSh7(\";`1`+`1`=`1`p`L`a` `r`a`v`;`)`\\x22`t`c`e`j`b`O`m`e`t`s`y`S`" ascii
    $s10 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aSh7(\";`)`\\x22`P`T`T`H`L`M`X`.`2`L`M`X`S`M`\\x22`(`t`c`e`j`b`O`X`" ascii
    $s11 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aSh7(\";`)`\\x22`l`y`k`0`o`n`r`t`c`i`/`m`o`c`.`s`r`e`i`r`r`e`t`x`o`" ascii
    $s12 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aSh7(\"/`*`@` `}`;`)`4`d`A`a`(`9`p`O`a` `n`r`u`t`e`r`;`)`(`e`s`o`l`" ascii
    $s13 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aSh7(\"\")), 1);" fullword ascii
    $s14 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aSh7(\";`)`\\x22`7`k`8`p`c`q`/`a`c`.`r`e`v`u`o`c`n`a`v`r`i`a`p`e`r`" ascii
    $s15 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aSh7(\";`)`\\x22`v`u`3`e`t`t`f`f`g`/`m`o`c`.`1`-`s`d`b`.`w`w`w`\\x2" ascii
    $s16 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aSh7(\";`)`'`/`%`P`M`E`T`%`'`(`]`'`s`g`n`i`r`t`S`t`n`e`m`n`o`r`i`v`" ascii
    $s17 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aSh7(\";`)`\\x22`7`g`u`b`g`m`y`c`q`/`m`o`c`.`t`f`o`s`y`l`e`s`i`w`" ascii
    $s18 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aSh7(\"}`;`h`t`a`P`t`r`o`h`S`.`0`l`H`W`a` `n`r`u`t`e`r`;`)`2`g`I`a`" ascii
    $s19 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aSh7(\";`5`w`Q`a` `+` `2`i`R`T`a`=`2`f`N`Q`a` `r`a`v\")), 1);" fullword ascii
    $s20 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aSh7(\";`\\x22`/`\\x22`+`\\x22`/`\\x22`+`\\x22`:`\\x22`+`\\x22`p`" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}