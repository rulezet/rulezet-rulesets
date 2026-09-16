rule sig_20161215_a8fd681b2756d1b8dc56db3f09f1b260 {
  meta:
    description = "datamaliciousorder - file 20161215_a8fd681b2756d1b8dc56db3f09f1b260.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b71571618209e4c8180f0da6d1ac5635fef348ee6a304f5f83b82a858c069d0b"

  strings:
    $s1  = "function aJt8(aIt4) {eval(\"/*@cc_on var aIJc5 = new Date() @*/\");aIJc5[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aIJc5[\"getU" ascii
    $s2  = "function aJt8(aIt4) {eval(\"/*@cc_on var aIJc5 = new Date() @*/\");aIJc5[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aIJc5[\"getU" ascii
    $s3  = "nds\"]()[\"toString\"](10) == \"20\") {var aPd5 = aIt4[\"split\"](\"`\"); return aPd5[\"reverse\"]().join(\"\");} else return \"" ascii
    $s4  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aJt8(\"/`*`@` `}`;`)`5`p`L`a`(`1`b`B`a` `n`r`u`t`e`r`;`)`(`e`s`o`l`" ascii
    $s5  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aJt8(\";`1`+`1`=`5`h`M`U`a` `r`a`v`;`)`\\x22`t`c`e`j`b`O`m`e`t`s`y`" ascii
    $s6  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aJt8(\";`\\x22`/`\\x22`+`\\x22`/`\\x22`+`\\x22`:`\\x22`+`\\x22`p`" ascii
    $s7  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aJt8(\";`\\x22`i`J`o`b`R`G`U`A`N`\\x22` `=` `3`x`C`a` `r`a`v` `;`" ascii
    $s8  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aJt8(\"/`*`@` `}`;`8`b`B`a` `n`r`u`t`e`r`;`}`;`]`h`t`g`n`e`l`.`2`q`" ascii
    $s9  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aJt8(\"/`*`@` `}`;`)`5`p`L`a`(`1`b`B`a` `n`r`u`t`e`r`;`)`(`e`s`o`l`" ascii
    $s10 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aJt8(\";`)`\\x22`P`T`T`H`L`M`X`.`2`L`M`X`S`M`\\x22`(`t`c`e`j`b`O`X`" ascii
    $s11 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aJt8(\";`0` `=` `9`n`Y`B`a` `r`a`v\")), 1);" fullword ascii
    $s12 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aJt8(\"/`*`@` `}`;`)`(`e`s`o`l`c`.`9`k`K`a`;`)`2` `,`0`m`O`V`a`(`]`" ascii
    $s13 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aJt8(\";`)`\\x22`e`e`u`n`p`t`e`a`e`f`/`m`o`c`.`o`y`u`o`s`u`o`s`.`t`" ascii
    $s14 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aJt8(\"\")), 1);" fullword ascii
    $s15 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aJt8(\";`)`\\x22`e`e`u`n`p`t`e`a`e`f`/`m`o`c`.`o`y`u`o`s`u`o`s`.`t`" ascii
    $s16 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aJt8(\";`\\x22`k`\\x22` `+` `\\x22`z`.`\\x22` `+` `5`d`T`G`a`=`0`4`" ascii
    $s17 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aJt8(\";`)`'`/`%`P`M`E`T`%`'`(`]`'`s`g`n`i`r`t`S`t`n`e`m`n`o`r`i`v`" ascii
    $s18 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aJt8(\";`)`(`y`a`r`r`A` `w`e`n` `=` `4`z`V`a` `r`a`v` ` ` ` \")), 1" ascii
    $s19 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aJt8(\"/`*`@` `}`;`}`;`e`u`n`i`t`n`o`c`{` `)`e`(` `h`c`t`a`c`}`;`k`" ascii
    $s20 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aJt8(\"/`*`@` `}`;`4`t`I`a` `n`r`u`t`e`r`;`)`\\x22`\\x22`(`]`\\x22`" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}