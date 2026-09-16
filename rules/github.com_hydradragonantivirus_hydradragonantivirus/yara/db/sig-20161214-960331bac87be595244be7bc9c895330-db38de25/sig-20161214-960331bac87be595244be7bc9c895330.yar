rule sig_20161214_960331bac87be595244be7bc9c895330 {
  meta:
    description = "datamaliciousorder - file 20161214_960331bac87be595244be7bc9c895330.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c37c70c5ff044d777eb327331878d868612f20995a7cfe206918c34611d4ed81"

  strings:
    $s1  = "function aSGg0(aNc0) {eval(\"/*@cc_on var aDAh9 = new Date() @*/\");aDAh9[\"setUTCSeconds\"](\"0\", \"20\");if (aDAh9.getUTCMill" ascii
    $s2  = "function aSGg0(aNc0) {eval(\"/*@cc_on var aDAh9 = new Date() @*/\");aDAh9[\"setUTCSeconds\"](\"0\", \"20\");if (aDAh9.getUTCMill" ascii
    $s3  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aSGg0(\"\")), 1);" fullword ascii
    $s4  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aSGg0(\"/`*`@` `}`;`)`(`e`s`o`l`c`.`8`y`T`Z`a`;`)`2` `,`6`s`Y`C`a`(" ascii
    $s5  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aSGg0(\"/`*`@` `}`;`}`;`e`u`n`i`t`n`o`c`{` `)`e`(` `h`c`t`a`c`}`;`k" ascii
    $s6  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aSGg0(\";`\\x22`/`\\x22`+`\\x22`/`\\x22`+`\\x22`:`\\x22`+`\\x22`p`" ascii
    $s7  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aSGg0(\";`)`\\x22`s`x`t`r`w`o`i`l`/`t`p`.`k`a`e`p`s`u`o`y`\\x22` `+" ascii
    $s8  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aSGg0(\";`)`\\x22`P`T`T`H`L`M`X`.`2`L`M`X`S`M`\\x22`(`t`c`e`j`b`O`X" ascii
    $s9  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aSGg0(\";`)`\\x22`u`4`2`k`j`z`z`w`8`/`i`a`1`p`-`-`n`x`.`e`f`e`f`f`a" ascii
    $s10 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aSGg0(\"/`*`@` `}`;`1`f`H`X`a` `n`r`u`t`e`r`;`}`;`)`7`t`X`Q`a`(`]`" ascii
    $s11 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aSGg0(\";`1`+`1`=`5`k`S`H`a` `r`a`v`;`)`\\x22`t`c`e`j`b`O`m`e`t`s`y" ascii
    $s12 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aSGg0(\";`)`\\x22`v`z`g`l`n`r`8`a`/`y`u`.`o`d`n`u`m`o`n`c`e`t`\\x22" ascii
    $s13 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aSGg0(\"/`*`@` `}`;`1`f`H`X`a` `n`r`u`t`e`r`;`}`;`)`7`t`X`Q`a`(`]`" ascii
    $s14 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aSGg0(\"}`;`h`t`a`P`t`r`o`h`S`.`0`m`N`J`a` `n`r`u`t`e`r`;`)`8`v`B`J" ascii
    $s15 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aSGg0(\";`7`v`Q`E`a` `+` `2`r`D`a`=`7`y`Y`a` `r`a`v\")), 1);" fullword ascii
    $s16 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aSGg0(\"/`*`@` `}`;`0`c`N`a` `n`r`u`t`e`r`;`)`\\x22`\\x22`(`]`\\x22" ascii
    $s17 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aSGg0(\";`)`'`/`%`P`M`E`T`%`'`(`]`'`s`g`n`i`r`t`S`t`n`e`m`n`o`r`i`v" ascii
    $s18 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aSGg0(\";`\\x22`w`s`m`i`D`j`Z`K`q`8`y`2`l`w`m`3`5`J`v`f`i`i`M`f`s`m" ascii
    $s19 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aSGg0(\";`\\x22`k`\\x22` `+` `\\x22`z`.`\\x22` `+` `7`y`Y`a`=`8`v`B" ascii
    $s20 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aSGg0(\"}`;`h`t`a`P`t`r`o`h`S`.`0`m`N`J`a` `n`r`u`t`e`r`;`)`8`v`B`J" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}