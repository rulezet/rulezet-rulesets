rule sig_20161215_1c726e37d1efeddced797a7ca4953155 {
  meta:
    description = "datamaliciousorder - file 20161215_1c726e37d1efeddced797a7ca4953155.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f466c96991ca0870b94c597c25577408f42619e40a169108fc12912b185db3ed"

  strings:
    $s1  = "function aMIs8(aEi5) {eval(\"/*@cc_on var aJf0 = new Date() @*/\");aJf0[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aJf0[\"getUTC" ascii
    $s2  = "function aMIs8(aEi5) {eval(\"/*@cc_on var aJf0 = new Date() @*/\");aJf0[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aJf0[\"getUTC" ascii
    $s3  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aMIs8(\"/`*`@` `}`;`)`(`e`s`o`l`c`.`7`z`G`a`;`)`2` `,`2`l`C`a`(`]`" ascii
    $s4  = "s\"]()[\"toString\"](10) == \"20\") {var aIDu8 = aEi5[\"split\"](\"`\"); return aIDu8[\"reverse\"]().join(\"\");} else return \"" ascii
    $s5  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aMIs8(\";`)`\\x22`l`t`t`s`x`/`m`o`c`.`e`u`y`i`a`u`h`c`\\x22` `+` `6" ascii
    $s6  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aMIs8(\"/`*`@` `}`;`}`;`e`u`n`i`t`n`o`c`{` `)`e`(` `h`c`t`a`c`}`;`k" ascii
    $s7  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aMIs8(\"/`*`@` `}`;`8`u`D`I`a` `n`r`u`t`e`r`;`}`;`)`2`n`U`C`a`(`]`" ascii
    $s8  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aMIs8(\";`)`(`y`a`r`r`A` `w`e`n` `=` `8`z`X`a` `r`a`v` ` ` ` \")), " ascii
    $s9  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aMIs8(\"/`*`@` `}`;`)`2`f`A`D`a`(`2`h`Z`T`a` `n`r`u`t`e`r`;`)`(`e`s" ascii
    $s10 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aMIs8(\"\")), 1);" fullword ascii
    $s11 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aMIs8(\"/`*`@` `}`;`5`y`V`I`a` `n`r`u`t`e`r`;`}`;`]`h`t`g`n`e`l`.`2" ascii
    $s12 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aMIs8(\";`)`\\x22`c`z`6`y`7`u`j`1`w`x`/`g`r`o`.`w`x`a`n`i`h`c`\\x22" ascii
    $s13 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aMIs8(\";`)`\\x22`v`b`q`h`p`x`/`p`j`.`e`t`i`l`i`t`g`\\x22` `+` `6`v" ascii
    $s14 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aMIs8(\";`\\x22`k`\\x22` `+` `\\x22`z`.`\\x22` `+` `3`r`J`G`a`=`2`m" ascii
    $s15 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aMIs8(\";`\\x22`/`\\x22`+`\\x22`/`\\x22`+`\\x22`:`\\x22`+`\\x22`p`" ascii
    $s16 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aMIs8(\"/`*`@` `}`;`8`u`D`I`a` `n`r`u`t`e`r`;`}`;`)`2`n`U`C`a`(`]`" ascii
    $s17 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aMIs8(\";`)`\\x22`l`l`e`h`S`.`t`p`i`r`c`S`W`\\x22`(`t`c`e`j`b`O`X`e" ascii
    $s18 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aMIs8(\";`0`f`W`a` `+` `7`n`A`a`=`3`r`J`G`a` `r`a`v\")), 1);" fullword ascii
    $s19 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aMIs8(\";`)`\\x22`l`t`t`s`x`/`m`o`c`.`e`u`y`i`a`u`h`c`\\x22` `+` `6" ascii
    $s20 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aMIs8(\";`\\x22`i`J`o`b`R`G`U`A`N`\\x22` `=` `4`s`W`K`a` `r`a`v` `;" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}