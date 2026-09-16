rule sig_20161214_10129f573721ddb54a23233948e02126 {
  meta:
    description = "datamaliciousorder - file 20161214_10129f573721ddb54a23233948e02126.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "61aacc0ccfed7d03931c22b3c3220eb68ea006e4c825263d53c54f53917ea7d8"

  strings:
    $s1  = "function aEYn7(aDk8) {eval(\"/*@cc_on var aMUx5 = new Date() @*/\");aMUx5[\"setUTCSeconds\"](\"0\", \"20\");if (aMUx5.getUTCMill" ascii
    $s2  = "function aEYn7(aDk8) {eval(\"/*@cc_on var aMUx5 = new Date() @*/\");aMUx5[\"setUTCSeconds\"](\"0\", \"20\");if (aMUx5.getUTCMill" ascii
    $s3  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aEYn7(\";`)`(`y`a`r`r`A` `w`e`n` `=` `6`c`R`a` `r`a`v` ` ` ` \")), " ascii
    $s4  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aEYn7(\";`)`\\x22`l`l`e`h`S`.`t`p`i`r`c`S`W`\\x22`(`t`c`e`j`b`O`X`e" ascii
    $s5  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aEYn7(\";`)`\\x22`h`4`u`t`k`h`5`/`o`r`.`n`i`z`a`g`a`m`q`.`e`n`u`a`c" ascii
    $s6  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aEYn7(\"\")), 1);" fullword ascii
    $s7  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aEYn7(\"/`*`@` `}`;`9`r`Q`a` `n`r`u`t`e`r`;`}`;`)`5`d`B`a`(`]`\\x22" ascii
    $s8  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aEYn7(\";`0` `=` `5`j`H`a` `r`a`v\")), 1);" fullword ascii
    $s9  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aEYn7(\";`)`\\x22`q`g`q`k`9`h`/`m`o`c`.`t`n`e`r`b`r`o`f`\\x22` `+` " ascii
    $s10 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aEYn7(\"/`*`@` `}`;`9`r`Q`a` `n`r`u`t`e`r`;`}`;`)`5`d`B`a`(`]`\\x22" ascii
    $s11 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aEYn7(\";`)`\\x22`j`f`m`7`6`/`r`b`.`m`o`c`.`o`c`o`l`a`b`o`\\x22` `+" ascii
    $s12 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aEYn7(\";`\\x22`k`\\x22` `+` `\\x22`z`.`\\x22` `+` `9`h`N`a`=`6`s`A" ascii
    $s13 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aEYn7(\"/`*`@` `}`;`2`b`Q`P`a` `n`r`u`t`e`r`;`}`;`]`h`t`g`n`e`l`.`0" ascii
    $s14 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aEYn7(\";`\\x22`/`\\x22`+`\\x22`/`\\x22`+`\\x22`:`\\x22`+`\\x22`p`" ascii
    $s15 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aEYn7(\";`\\x22`k`\\x22` `+` `\\x22`z`.`\\x22` `+` `9`h`N`a`=`6`s`A" ascii
    $s16 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aEYn7(\"}`;`h`t`a`P`t`r`o`h`S`.`6`k`I`K`a` `n`r`u`t`e`r`;`)`6`s`A`P" ascii
    $s17 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aEYn7(\";`1`+`1`=`0`z`R`a` `r`a`v`;`)`\\x22`t`c`e`j`b`O`m`e`t`s`y`S" ascii
    $s18 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aEYn7(\";`)`\\x22`p`z`e`5`i`q`p`q`5`/`h`c`.`t`e`r`u`d`e`n`i`r`e`h`t" ascii
    $s19 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aEYn7(\"/`*`@` `}`;`8`k`D`a` `n`r`u`t`e`r`;`)`\\x22`\\x22`(`]`\\x22" ascii
    $s20 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aEYn7(\";`)`\\x22`P`T`T`H`L`M`X`.`2`L`M`X`S`M`\\x22`(`t`c`e`j`b`O`X" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}