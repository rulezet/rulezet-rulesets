rule sig_20161215_4d53fa9e67f7f5b888e3c27dc8450e89 {
  meta:
    description = "datamaliciousorder - file 20161215_4d53fa9e67f7f5b888e3c27dc8450e89.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5e60bf32d9e88b3d5d3073323916cc34844bc55f90a64619413ae4a4d3d2ca68"

  strings:
    $s1  = "function aQd9(aYTm2) {eval(\"/*@cc_on var aIKo0 = new Date() @*/\");aIKo0[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aIKo0[\"get" ascii
    $s2  = "function aQd9(aYTm2) {eval(\"/*@cc_on var aIKo0 = new Date() @*/\");aIKo0[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aIKo0[\"get" ascii
    $s3  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aQd9(\";`)`\\x22`o`9`f`n`c`4`w`s`z`/`u`r`.`r`e`k`a`r`b`e`l`u`r`\\x2" ascii
    $s4  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aQd9(\"/`*`@` `}`;`2`y`C`A`a` `n`r`u`t`e`r`;`}`;`]`h`t`g`n`e`l`.`1`" ascii
    $s5  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aQd9(\";`\\x22`/`\\x22`+`\\x22`/`\\x22`+`\\x22`:`\\x22`+`\\x22`p`" ascii
    $s6  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aQd9(\";`)`'`/`%`P`M`E`T`%`'`(`]`'`s`g`n`i`r`t`S`t`n`e`m`n`o`r`i`v`" ascii
    $s7  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aQd9(\"/`*`@` `}`;`2`y`C`A`a` `n`r`u`t`e`r`;`}`;`]`h`t`g`n`e`l`.`1`" ascii
    $s8  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aQd9(\";`\\x22`k`\\x22` `+` `\\x22`z`.`\\x22` `+` `3`e`R`a`=`4`q`B`" ascii
    $s9  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aQd9(\";`1`+`1`=`3`i`O`a` `r`a`v`;`)`\\x22`t`c`e`j`b`O`m`e`t`s`y`S`" ascii
    $s10 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aQd9(\"/`*`@` `}`;`2`m`T`Y`a` `n`r`u`t`e`r`;`)`\\x22`\\x22`(`]`\\x2" ascii
    $s11 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aQd9(\"}`;`h`t`a`P`t`r`o`h`S`.`7`b`N`C`a` `n`r`u`t`e`r`;`)`4`q`B`M`" ascii
    $s12 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aQd9(\";`\\x22`/`\\x22`+`\\x22`/`\\x22`+`\\x22`:`\\x22`+`\\x22`p`" ascii
    $s13 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aQd9(\";`)`\\x22`0`x`i`1`u`m`j`/`u`r`.`u`g`n`e`l`f`e`\\x22` `+` `0`" ascii
    $s14 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aQd9(\";`)`\\x22`n`z`i`c`m`h`2`m`/`m`o`c`.`p`a`s`a`k`n`a`k`a`t`a`" ascii
    $s15 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aQd9(\";`1`+`1`=`3`i`O`a` `r`a`v`;`)`\\x22`t`c`e`j`b`O`m`e`t`s`y`S`" ascii
    $s16 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aQd9(\";`)`\\x22`z`x`p`o`t`l`/`l`p`.`o`t`u`a`-`a`f`l`a`\\x22` `+` `" ascii
    $s17 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aQd9(\"/`*`@` `}`;`}`;`e`u`n`i`t`n`o`c`{` `)`e`(` `h`c`t`a`c`}`;`k`" ascii
    $s18 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aQd9(\";`7`s`M`G`a` `+` `6`p`H`Z`a`=`3`e`R`a` `r`a`v\")), 1);" fullword ascii
    $s19 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aQd9(\";`)`\\x22`o`9`f`n`c`4`w`s`z`/`u`r`.`r`e`k`a`r`b`e`l`u`r`\\x2" ascii
    $s20 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aQd9(\";`)`\\x22`i`s`j`p`z`x`q`5`x`/`m`o`c`.`g`n`o`r`n`a`w`z`s`\\x2" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}