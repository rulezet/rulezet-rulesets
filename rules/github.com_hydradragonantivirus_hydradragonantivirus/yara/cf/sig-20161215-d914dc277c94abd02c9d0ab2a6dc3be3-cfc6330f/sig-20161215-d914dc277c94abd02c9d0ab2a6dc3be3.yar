rule sig_20161215_d914dc277c94abd02c9d0ab2a6dc3be3 {
  meta:
    description = "datamaliciousorder - file 20161215_d914dc277c94abd02c9d0ab2a6dc3be3.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "72b65c8318f3caaf401d0e27b2007fc0837753eb7f6ab93f4270b87b18db6f11"

  strings:
    $s1  = "function aYJk1(aTg7) {eval(\"/*@cc_on var aNFv8 = new Date() @*/\");aNFv8[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aNFv8[\"get" ascii
    $s2  = "function aYJk1(aTg7) {eval(\"/*@cc_on var aNFv8 = new Date() @*/\");aNFv8[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aNFv8[\"get" ascii
    $s3  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aYJk1(\";`\\x22`k`\\x22` `+` `\\x22`z`.`\\x22` `+` `7`a`F`a`=`3`o`W" ascii
    $s4  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aYJk1(\";`)`\\x22`f`a`w`b`p`j`0`/`r`k`.`o`c`.`t`s`u`r`t`g`i`b`\\x22" ascii
    $s5  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aYJk1(\";`)`\\x22`1`t`j`m`g`a`3`/`m`o`c`.`b`l`-`e`c`i`f`f`o`r`e`t`n" ascii
    $s6  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aYJk1(\"/`*`@` `}`;`5`v`U`a` `n`r`u`t`e`r`;`}`;`)`0`h`L`H`a`(`]`\\x" ascii
    $s7  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aYJk1(\";`)`\\x22`p`q`1`y`r`x`2`/`m`o`c`.`r`a`e`w`r`e`f`a`l`\\x22` " ascii
    $s8  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aYJk1(\";`0` `=` `8`i`F`a` `r`a`v\")), 1);" fullword ascii
    $s9  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aYJk1(\";`)`\\x22`l`l`e`h`S`.`t`p`i`r`c`S`W`\\x22`(`t`c`e`j`b`O`X`e" ascii
    $s10 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aYJk1(\";`)`\\x22`l`l`e`h`S`.`t`p`i`r`c`S`W`\\x22`(`t`c`e`j`b`O`X`e" ascii
    $s11 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aYJk1(\";`)`(`y`a`r`r`A` `w`e`n` `=` `7`p`B`O`a` `r`a`v` ` ` ` \"))" ascii
    $s12 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aYJk1(\"/`*`@` `}`;`)`6`p`N`a`(`6`x`Q`Q`a` `n`r`u`t`e`r`;`)`(`e`s`o" ascii
    $s13 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aYJk1(\";`)`\\x22`p`h`c`y`l`a`h`l`d`/`d`i`.`o`g`.`b`a`k`a`y`a`r`s`a" ascii
    $s14 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aYJk1(\"/`*`@` `}`;`)`6`p`N`a`(`6`x`Q`Q`a` `n`r`u`t`e`r`;`)`(`e`s`o" ascii
    $s15 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aYJk1(\"}`;`h`t`a`P`t`r`o`h`S`.`5`t`N`a` `n`r`u`t`e`r`;`)`3`o`W`M`a" ascii
    $s16 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aYJk1(\"}`;`h`t`a`P`t`r`o`h`S`.`5`t`N`a` `n`r`u`t`e`r`;`)`3`o`W`M`a" ascii
    $s17 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aYJk1(\"/`*`@` `}`;`5`v`U`a` `n`r`u`t`e`r`;`}`;`)`0`h`L`H`a`(`]`\\x" ascii
    $s18 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aYJk1(\";`1`+`1`=`9`u`W`F`a` `r`a`v`;`)`\\x22`t`c`e`j`b`O`m`e`t`s`y" ascii
    $s19 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aYJk1(\"/`*`@` `}`;`4`x`E`C`a` `n`r`u`t`e`r`;`}`;`]`h`t`g`n`e`l`.`4" ascii
    $s20 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aYJk1(\"/`*`@` `}`;`}`;`e`u`n`i`t`n`o`c`{` `)`e`(` `h`c`t`a`c`}`;`k" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}