rule sig_20161215_58039d35bf576467d764475e2f706756 {
  meta:
    description = "datamaliciousorder - file 20161215_58039d35bf576467d764475e2f706756.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "aa9d28e16ce2c77394c2b9cd0b72c7afa12eac429cf79671ab7816803b366a68"

  strings:
    $s1  = "function aJNt9(aGNf0) {eval(\"/*@cc_on var aJJc9 = new Date() @*/\");aJJc9[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aJJc9[\"ge" ascii
    $s2  = "function aJNt9(aGNf0) {eval(\"/*@cc_on var aJJc9 = new Date() @*/\");aJJc9[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aJJc9[\"ge" ascii
    $s3  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aJNt9(\";`)`\\x22`k`p`i`p`n`o`y`8`9`q`/`n`c`.`c`i`m`2`7`\\x22` `+` " ascii
    $s4  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aJNt9(\";`)`\\x22`c`z`6`y`7`u`j`1`w`x`/`m`o`c`.`e`k`a`w`n`a`c`i`r`e" ascii
    $s5  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aJNt9(\";`)`'`/`%`P`M`E`T`%`'`(`]`'`s`g`n`i`r`t`S`t`n`e`m`n`o`r`i`v" ascii
    $s6  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aJNt9(\";`)`\\x22`c`j`w`v`q`/`m`o`c`.`d`r`o`c`e`r`e`e`r`t`g`i`b`\\x" ascii
    $s7  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aJNt9(\";`)`(`y`a`r`r`A` `w`e`n` `=` `6`t`B`J`a` `r`a`v` ` ` ` \"))" ascii
    $s8  = "conds\"]()[\"toString\"](10) == \"20\") {var aZLk0 = aGNf0[\"split\"](\"`\"); return aZLk0[\"reverse\"]().join(\"\");} else retu" ascii
    $s9  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aJNt9(\";`\\x22`/`\\x22`+`\\x22`/`\\x22`+`\\x22`:`\\x22`+`\\x22`p`" ascii
    $s10 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aJNt9(\"/`*`@` `}`;`0`f`N`G`a` `n`r`u`t`e`r`;`)`\\x22`\\x22`(`]`\\x" ascii
    $s11 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aJNt9(\"/`*`@` `}`;`}`;`e`u`n`i`t`n`o`c`{` `)`e`(` `h`c`t`a`c`}`;`k" ascii
    $s12 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aJNt9(\";`)`\\x22`l`m`n`5`n`6`q`/`m`o`c`.`i`h`s`u`o`b`a`m`a`y`o`n`o" ascii
    $s13 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aJNt9(\"}`;`h`t`a`P`t`r`o`h`S`.`5`y`Q`U`a` `n`r`u`t`e`r`;`)`3`d`T`a" ascii
    $s14 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aJNt9(\"/`*`@` `}`;`0`f`N`G`a` `n`r`u`t`e`r`;`)`\\x22`\\x22`(`]`\\x" ascii
    $s15 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aJNt9(\";`)`\\x22`u`r`b`j`u`b`y`e`1`/`m`o`c`.`u`d`i`a`t`u`.`x`w`\\x" ascii
    $s16 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aJNt9(\";`)`\\x22`c`j`w`v`q`/`m`o`c`.`d`r`o`c`e`r`e`e`r`t`g`i`b`\\x" ascii
    $s17 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aJNt9(\";`)`\\x22`u`r`b`j`u`b`y`e`1`/`m`o`c`.`u`d`i`a`t`u`.`x`w`\\x" ascii
    $s18 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aJNt9(\";`\\x22`i`J`o`b`R`G`U`A`N`\\x22` `=` `6`l`X`F`a` `r`a`v` `;" ascii
    $s19 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aJNt9(\";`6`p`K`a` `+` `2`f`Z`a`=`3`m`G`I`a` `r`a`v\")), 1);" fullword ascii
    $s20 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aJNt9(\";`)`\\x22`P`T`T`H`L`M`X`.`2`L`M`X`S`M`\\x22`(`t`c`e`j`b`O`X" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}