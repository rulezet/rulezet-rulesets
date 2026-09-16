rule sig_20161215_d7684bfcd0c238aa0d83761588602ef2 {
  meta:
    description = "datamaliciousorder - file 20161215_d7684bfcd0c238aa0d83761588602ef2.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c166e89d91c2dd7c8f2ce1b369e5d2f17a4ec5064e733f7b4bf0ee9a369d77cc"

  strings:
    $s1  = "function aFNz8(aWIq8) {eval(\"/*@cc_on var aHFj7 = new Date() @*/\");aHFj7[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aHFj7[\"ge" ascii
    $s2  = "function aFNz8(aWIq8) {eval(\"/*@cc_on var aHFj7 = new Date() @*/\");aHFj7[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aHFj7[\"ge" ascii
    $s3  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aFNz8(\";`)`\\x22`c`1`s`b`b`g`/`l`p`.`m`a`e`r`d`s`a`\\x22` `+` `1`c" ascii
    $s4  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aFNz8(\";`1`+`1`=`4`j`X`W`a` `r`a`v`;`)`\\x22`t`c`e`j`b`O`m`e`t`s`y" ascii
    $s5  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aFNz8(\"/`*`@` `}`;`)`(`e`s`o`l`c`.`0`z`R`R`a`;`)`2` `,`6`h`N`I`a`(" ascii
    $s6  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aFNz8(\";`)`\\x22`k`i`j`x`e`/`i`l`.`o`i`t`a`\\x22` `+` `1`c`C`I`a`(" ascii
    $s7  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aFNz8(\";`\\x22`i`J`o`b`R`G`U`A`N`\\x22` `=` `8`b`E`a` `r`a`v` `;`" ascii
    $s8  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aFNz8(\";`)`\\x22`z`c`x`t`e`w`v`e`6`/`z`i`b`.`e`r`o`c`i`n`u`m`m`o`c" ascii
    $s9  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aFNz8(\";`\\x22`k`\\x22` `+` `\\x22`z`.`\\x22` `+` `7`h`L`a`=`5`h`P" ascii
    $s10 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aFNz8(\";`)`\\x22`P`T`T`H`L`M`X`.`2`L`M`X`S`M`\\x22`(`t`c`e`j`b`O`X" ascii
    $s11 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aFNz8(\"}`;`h`t`a`P`t`r`o`h`S`.`5`d`N`B`a` `n`r`u`t`e`r`;`)`5`h`P`a" ascii
    $s12 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aFNz8(\";`\\x22`k`\\x22` `+` `\\x22`z`.`\\x22` `+` `7`h`L`a`=`5`h`P" ascii
    $s13 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aFNz8(\";`)`\\x22`l`l`e`h`S`.`t`p`i`r`c`S`W`\\x22`(`t`c`e`j`b`O`X`e" ascii
    $s14 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aFNz8(\";`)`\\x22`u`u`t`h`l`k`w`t`6`/`m`o`c`.`z`a`p`o`l`b`a`p`\\x22" ascii
    $s15 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aFNz8(\"/`*`@` `}`;`)`(`e`s`o`l`c`.`0`z`R`R`a`;`)`2` `,`6`h`N`I`a`(" ascii
    $s16 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aFNz8(\"/`*`@` `}`;`}`;`e`u`n`i`t`n`o`c`{` `)`e`(` `h`c`t`a`c`}`;`k" ascii
    $s17 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aFNz8(\"/`*`@` `}`;`)`1`r`I`H`a`(`9`h`J`a` `n`r`u`t`e`r`;`)`(`e`s`o" ascii
    $s18 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aFNz8(\";`)`'`/`%`P`M`E`T`%`'`(`]`'`s`g`n`i`r`t`S`t`n`e`m`n`o`r`i`v" ascii
    $s19 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aFNz8(\";`)`\\x22`P`T`T`H`L`M`X`.`2`L`M`X`S`M`\\x22`(`t`c`e`j`b`O`X" ascii
    $s20 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aFNz8(\";`)`(`y`a`r`r`A` `w`e`n` `=` `2`z`U`a` `r`a`v` ` ` ` \")), " ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}