rule sig_20161215_a63202e33481e337c6334d4cbe181d6d {
  meta:
    description = "datamaliciousorder - file 20161215_a63202e33481e337c6334d4cbe181d6d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "42fd23d77f0b1163f67a1ebf2e4bd357dffca7e784c728750683ac51aea707fe"

  strings:
    $s1  = "function aIKa1(aLp5) {eval(\"/*@cc_on var aUy5 = new Date() @*/\");aUy5[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aUy5[\"getUTC" ascii
    $s2  = "function aIKa1(aLp5) {eval(\"/*@cc_on var aUy5 = new Date() @*/\");aUy5[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aUy5[\"getUTC" ascii
    $s3  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aIKa1(\"/`*`@` `}`;`5`p`L`a` `n`r`u`t`e`r`;`)`\\x22`\\x22`(`]`\\x22" ascii
    $s4  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aIKa1(\";`1`+`1`=`1`c`N`I`a` `r`a`v`;`)`\\x22`t`c`e`j`b`O`m`e`t`s`y" ascii
    $s5  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aIKa1(\";`)`\\x22`z`c`x`t`e`w`v`e`6`/`z`i`b`.`e`r`o`c`i`n`u`m`m`o`c" ascii
    $s6  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aIKa1(\";`)`\\x22`P`T`T`H`L`M`X`.`2`L`M`X`S`M`\\x22`(`t`c`e`j`b`O`X" ascii
    $s7  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aIKa1(\";`\\x22`i`J`o`b`R`G`U`A`N`\\x22` `=` `2`f`M`Y`a` `r`a`v` `;" ascii
    $s8  = "s\"]()[\"toString\"](10) == \"20\") {var aOFb6 = aLp5[\"split\"](\"`\"); return aOFb6[\"reverse\"]().join(\"\");} else return \"" ascii
    $s9  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aIKa1(\"/`*`@` `}`;`7`z`O`a` `n`r`u`t`e`r`;`}`;`]`h`t`g`n`e`l`.`1`a" ascii
    $s10 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aIKa1(\";`\\x22`/`\\x22`+`\\x22`/`\\x22`+`\\x22`:`\\x22`+`\\x22`p`" ascii
    $s11 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aIKa1(\";`)`'`/`%`P`M`E`T`%`'`(`]`'`s`g`n`i`r`t`S`t`n`e`m`n`o`r`i`v" ascii
    $s12 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aIKa1(\";`)`(`y`a`r`r`A` `w`e`n` `=` `5`k`L`a` `r`a`v` ` ` ` \")), " ascii
    $s13 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aIKa1(\";`1`+`1`=`1`c`N`I`a` `r`a`v`;`)`\\x22`t`c`e`j`b`O`m`e`t`s`y" ascii
    $s14 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aIKa1(\";`\\x22`i`J`o`b`R`G`U`A`N`\\x22` `=` `2`f`M`Y`a` `r`a`v` `;" ascii
    $s15 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aIKa1(\"/`*`@` `}`;`6`b`F`O`a` `n`r`u`t`e`r`;`}`;`)`2`u`O`L`a`(`]`" ascii
    $s16 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aIKa1(\"}`;`h`t`a`P`t`r`o`h`S`.`4`m`Q`E`a` `n`r`u`t`e`r`;`)`4`w`Z`a" ascii
    $s17 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aIKa1(\";`\\x22`k`\\x22` `+` `\\x22`z`.`\\x22` `+` `7`j`H`a`=`4`w`Z" ascii
    $s18 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aIKa1(\"/`*`@` `}`;`5`p`L`a` `n`r`u`t`e`r`;`)`\\x22`\\x22`(`]`\\x22" ascii
    $s19 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aIKa1(\"}`;`h`t`a`P`t`r`o`h`S`.`4`m`Q`E`a` `n`r`u`t`e`r`;`)`4`w`Z`a" ascii
    $s20 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aIKa1(\";`\\x22`/`\\x22`+`\\x22`/`\\x22`+`\\x22`:`\\x22`+`\\x22`p`" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}