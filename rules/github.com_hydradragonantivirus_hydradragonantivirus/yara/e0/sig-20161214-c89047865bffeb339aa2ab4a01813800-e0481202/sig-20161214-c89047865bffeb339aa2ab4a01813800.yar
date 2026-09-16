rule sig_20161214_c89047865bffeb339aa2ab4a01813800 {
  meta:
    description = "datamaliciousorder - file 20161214_c89047865bffeb339aa2ab4a01813800.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "20853875ef50771fca79a919062c686afc1291486d17cb3b5a7e67239baae1d1"

  strings:
    $s1  = "function aLYt7(aMb8) {eval(\"/*@cc_on var aLQc0 = new Date() @*/\");aLQc0[\"setUTCSeconds\"](\"0\", \"20\");if (aLQc0.getUTCMill" ascii
    $s2  = "function aLYt7(aMb8) {eval(\"/*@cc_on var aLQc0 = new Date() @*/\");aLQc0[\"setUTCSeconds\"](\"0\", \"20\");if (aLQc0.getUTCMill" ascii
    $s3  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aLYt7(\"/`*`@` `}`;`)`9`v`C`a`(`1`k`C`a` `n`r`u`t`e`r`;`)`(`e`s`o`l" ascii
    $s4  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aLYt7(\"}`;`h`t`a`P`t`r`o`h`S`.`1`o`Z`a` `n`r`u`t`e`r`;`)`7`a`X`a`(" ascii
    $s5  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aLYt7(\"/`*`@` `}`;`1`s`D`J`a` `n`r`u`t`e`r`;`}`;`)`2`o`S`W`a`(`]`" ascii
    $s6  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aLYt7(\";`)`\\x22`l`l`e`h`S`.`t`p`i`r`c`S`W`\\x22`(`t`c`e`j`b`O`X`e" ascii
    $s7  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aLYt7(\";`)`\\x22`7`w`1`o`y`d`/`m`o`c`.`n`g`i`s`e`d`m`e`r`a`u`q`s`." ascii
    $s8  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aLYt7(\"/`*`@` `}`;`8`b`M`a` `n`r`u`t`e`r`;`)`\\x22`\\x22`(`]`\\x22" ascii
    $s9  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aLYt7(\"/`*`@` `}`;`}`;`e`u`n`i`t`n`o`c`{` `)`e`(` `h`c`t`a`c`}`;`k" ascii
    $s10 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aLYt7(\";`)`\\x22`7`w`1`o`y`d`/`m`o`c`.`n`g`i`s`e`d`m`e`r`a`u`q`s`." ascii
    $s11 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aLYt7(\";`)`\\x22`c`z`6`y`7`u`j`1`w`x`/`g`r`o`.`w`x`a`n`i`h`c`\\x22" ascii
    $s12 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aLYt7(\";`)`(`y`a`r`r`A` `w`e`n` `=` `1`i`P`F`a` `r`a`v` ` ` ` \"))" ascii
    $s13 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aLYt7(\";`\\x22`w`s`m`i`D`j`Z`K`q`8`y`2`l`w`m`3`5`J`v`f`i`i`M`f`s`m" ascii
    $s14 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aLYt7(\";`)`\\x22`u`6`b`s`z`y`p`d`/`m`o`c`.`b`g`s`o`f`e`d`e`h`\\x22" ascii
    $s15 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aLYt7(\"/`*`@` `}`;`)`(`e`s`o`l`c`.`7`l`Y`I`a`;`)`2` `,`6`v`E`a`(`]" ascii
    $s16 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aLYt7(\";`\\x22`/`\\x22`+`\\x22`/`\\x22`+`\\x22`:`\\x22`+`\\x22`p`" ascii
    $s17 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aLYt7(\";`)`\\x22`P`T`T`H`L`M`X`.`2`L`M`X`S`M`\\x22`(`t`c`e`j`b`O`X" ascii
    $s18 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aLYt7(\"/`*`@` `}`;`8`b`M`a` `n`r`u`t`e`r`;`)`\\x22`\\x22`(`]`\\x22" ascii
    $s19 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aLYt7(\";`\\x22`k`\\x22` `+` `\\x22`z`.`\\x22` `+` `8`v`E`R`a`=`7`a" ascii
    $s20 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aLYt7(\"/`*`@` `}`;`0`h`D`U`a` `n`r`u`t`e`r`;`}`;`]`h`t`g`n`e`l`.`3" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}