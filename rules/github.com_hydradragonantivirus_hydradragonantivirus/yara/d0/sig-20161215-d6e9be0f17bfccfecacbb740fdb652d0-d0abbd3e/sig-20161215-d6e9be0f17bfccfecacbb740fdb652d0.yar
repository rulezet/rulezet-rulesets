rule sig_20161215_d6e9be0f17bfccfecacbb740fdb652d0 {
  meta:
    description = "datamaliciousorder - file 20161215_d6e9be0f17bfccfecacbb740fdb652d0.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4d903f2e90d2a809f95edcc6f6598e7045f38381fc71bed8da3a79e38199dbda"

  strings:
    $s1  = "function aKa8(aOt1) {eval(\"/*@cc_on var aJg8 = new Date() @*/\");aJg8[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aJg8[\"getUTCM" ascii
    $s2  = "function aKa8(aOt1) {eval(\"/*@cc_on var aJg8 = new Date() @*/\");aJg8[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aJg8[\"getUTCM" ascii
    $s3  = "\"]()[\"toString\"](10) == \"20\") {var aZv9 = aOt1[\"split\"](\"`\"); return aZv9[\"reverse\"]().join(\"\");} else return \"\";" ascii
    $s4  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aKa8(\"/`*`@` `}`;`)`1`z`E`M`a`(`5`d`Y`D`a` `n`r`u`t`e`r`;`)`(`e`s`" ascii
    $s5  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aKa8(\";`\\x22`/`\\x22`+`\\x22`/`\\x22`+`\\x22`:`\\x22`+`\\x22`p`" ascii
    $s6  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aKa8(\";`)`\\x22`0`8`v`i`r`u`g`j`m`/`m`o`c`.`s`y`b`u`s`\\x22` `+` `" ascii
    $s7  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aKa8(\";`)`\\x22`P`T`T`H`L`M`X`.`2`L`M`X`S`M`\\x22`(`t`c`e`j`b`O`X`" ascii
    $s8  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aKa8(\"/`*`@` `}`;`1`t`O`a` `n`r`u`t`e`r`;`)`\\x22`\\x22`(`]`\\x22`" ascii
    $s9  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aKa8(\";`)`\\x22`q`z`2`b`z`i`g`/`g`r`o`.`t`u`m`a`l`a`m`\\x22` `+` `" ascii
    $s10 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aKa8(\"}`;`h`t`a`P`t`r`o`h`S`.`6`d`K`X`a` `n`r`u`t`e`r`;`)`5`z`G`R`" ascii
    $s11 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aKa8(\";`)`\\x22`j`o`o`6`p`c`9`w`z`n`/`m`o`c`.`e`c`i`-`p`e`e`d`.`n`" ascii
    $s12 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aKa8(\"/`*`@` `}`;`9`v`Z`a` `n`r`u`t`e`r`;`}`;`)`5`g`I`a`(`]`\\x22`" ascii
    $s13 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aKa8(\";`)`\\x22`4`x`p`s`u`s`c`n`/`m`o`c`.`s`b`e`w`0`5`.`d`e`l`t`i`" ascii
    $s14 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aKa8(\"/`*`@` `}`;`)`(`e`s`o`l`c`.`0`z`L`F`a`;`)`2` `,`7`o`Q`Z`a`(`" ascii
    $s15 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aKa8(\";`)`\\x22`P`T`T`H`L`M`X`.`2`L`M`X`S`M`\\x22`(`t`c`e`j`b`O`X`" ascii
    $s16 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aKa8(\"/`*`@` `}`;`}`;`e`u`n`i`t`n`o`c`{` `)`e`(` `h`c`t`a`c`}`;`k`" ascii
    $s17 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aKa8(\";`)`\\x22`q`z`2`b`z`i`g`/`g`r`o`.`t`u`m`a`l`a`m`\\x22` `+` `" ascii
    $s18 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aKa8(\"/`*`@` `}`;`)`(`e`s`o`l`c`.`0`z`L`F`a`;`)`2` `,`7`o`Q`Z`a`(`" ascii
    $s19 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aKa8(\";`1`+`1`=`0`i`Z`V`a` `r`a`v`;`)`\\x22`t`c`e`j`b`O`m`e`t`s`y`" ascii
    $s20 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aKa8(\";`)`(`y`a`r`r`A` `w`e`n` `=` `4`f`B`X`a` `r`a`v` ` ` ` \"))," ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}