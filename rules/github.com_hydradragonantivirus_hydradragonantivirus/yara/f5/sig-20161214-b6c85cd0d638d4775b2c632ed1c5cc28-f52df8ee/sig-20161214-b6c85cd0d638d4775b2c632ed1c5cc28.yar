rule sig_20161214_b6c85cd0d638d4775b2c632ed1c5cc28 {
  meta:
    description = "datamaliciousorder - file 20161214_b6c85cd0d638d4775b2c632ed1c5cc28.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2e0155a2281bf866f7cc8e7bfc7bce899b7c429ae22efdc5e34c8515a2c67c36"

  strings:
    $s1  = "function aZAr9(aSVc7) {eval(\"/*@cc_on var aHu7 = new Date() @*/\");aHu7[\"setUTCSeconds\"](\"0\", \"20\");if (aHu7.getUTCMillis" ascii
    $s2  = "function aZAr9(aSVc7) {eval(\"/*@cc_on var aHu7 = new Date() @*/\");aHu7[\"setUTCSeconds\"](\"0\", \"20\");if (aHu7.getUTCMillis" ascii
    $s3  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aZAr9(\";`\\x22`k`\\x22` `+` `\\x22`z`.`\\x22` `+` `4`c`W`F`a`=`4`l" ascii
    $s4  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aZAr9(\";`)`\\x22`P`T`T`H`L`M`X`.`2`L`M`X`S`M`\\x22`(`t`c`e`j`b`O`X" ascii
    $s5  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aZAr9(\"/`*`@` `}`;`}`;`e`u`n`i`t`n`o`c`{` `)`e`(` `h`c`t`a`c`}`;`k" ascii
    $s6  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aZAr9(\";`)`\\x22`f`g`s`i`n`b`7`/`z`c`.`k`a`l`m`u`h`.`4`6`n`a`m`o`r" ascii
    $s7  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aZAr9(\"/`*`@` `}`;`7`c`V`S`a` `n`r`u`t`e`r`;`)`\\x22`\\x22`(`]`\\x" ascii
    $s8  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aZAr9(\";`1`+`1`=`5`a`R`X`a` `r`a`v`;`)`\\x22`t`c`e`j`b`O`m`e`t`s`y" ascii
    $s9  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aZAr9(\";`)`(`y`a`r`r`A` `w`e`n` `=` `1`w`N`M`a` `r`a`v` ` ` ` \"))" ascii
    $s10 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aZAr9(\";`)`\\x22`a`c`4`e`q`k`/`m`o`c`.`8`1`3`x`t`\\x22` `+` `9`g`D" ascii
    $s11 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aZAr9(\";`)`\\x22`p`c`6`k`7`/`u`r`.`t`s`u`d`-`i`t`n`a`\\x22` `+` `9" ascii
    $s12 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aZAr9(\";`)`\\x22`l`l`e`h`S`.`t`p`i`r`c`S`W`\\x22`(`t`c`e`j`b`O`X`e" ascii
    $s13 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aZAr9(\";`\\x22`k`\\x22` `+` `\\x22`z`.`\\x22` `+` `4`c`W`F`a`=`4`l" ascii
    $s14 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aZAr9(\";`\\x22`/`\\x22`+`\\x22`/`\\x22`+`\\x22`:`\\x22`+`\\x22`p`" ascii
    $s15 = ".toString(10) == \"20\") {var aVm1 = aSVc7[\"split\"](\"`\"); return aVm1.reverse().join(\"\");} else return \"\";};" fullword ascii
    $s16 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aZAr9(\"/`*`@` `}`;`2`k`Y`a` `n`r`u`t`e`r`;`}`;`]`h`t`g`n`e`l`.`5`u" ascii
    $s17 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aZAr9(\"/`*`@` `}`;`)`(`e`s`o`l`c`.`2`y`F`J`a`;`)`2` `,`0`d`H`a`(`]" ascii
    $s18 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aZAr9(\";`\\x22`w`s`m`i`D`j`Z`K`q`8`y`2`l`w`m`3`5`J`v`f`i`i`M`f`s`m" ascii
    $s19 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aZAr9(\";`)`\\x22`f`g`s`i`n`b`7`/`z`c`.`k`a`l`m`u`h`.`4`6`n`a`m`o`r" ascii
    $s20 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aZAr9(\";`)`\\x22`p`c`6`k`7`/`u`r`.`t`s`u`d`-`i`t`n`a`\\x22` `+` `9" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}