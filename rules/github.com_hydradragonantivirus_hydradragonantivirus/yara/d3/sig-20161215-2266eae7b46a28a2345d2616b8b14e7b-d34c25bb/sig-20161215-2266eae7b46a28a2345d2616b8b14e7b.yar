rule sig_20161215_2266eae7b46a28a2345d2616b8b14e7b {
  meta:
    description = "datamaliciousorder - file 20161215_2266eae7b46a28a2345d2616b8b14e7b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "94207c224d36a7b28acebcf680f96fa5da2ed94393d62e8a5b56c28c988c9be6"

  strings:
    $s1  = "function aUSc0(aTj9) {eval(\"/*@cc_on var aUTm7 = new Date() @*/\");aUTm7[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aUTm7[\"get" ascii
    $s2  = "function aUSc0(aTj9) {eval(\"/*@cc_on var aUTm7 = new Date() @*/\");aUTm7[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aUTm7[\"get" ascii
    $s3  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aUSc0(\"/`*`@` `}`;`)`(`e`s`o`l`c`.`2`h`Q`Z`a`;`)`2` `,`1`h`I`R`a`(" ascii
    $s4  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aUSc0(\";`)`\\x22`p`h`c`y`l`a`h`l`d`/`d`i`.`o`g`.`b`a`k`a`y`a`r`s`a" ascii
    $s5  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aUSc0(\";`\\x22`/`\\x22`+`\\x22`/`\\x22`+`\\x22`:`\\x22`+`\\x22`p`" ascii
    $s6  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aUSc0(\"}`;`h`t`a`P`t`r`o`h`S`.`2`e`D`G`a` `n`r`u`t`e`r`;`)`6`m`I`T" ascii
    $s7  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aUSc0(\";`)`\\x22`p`q`1`y`r`x`2`/`m`o`c`.`r`a`e`w`r`e`f`a`l`\\x22` " ascii
    $s8  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aUSc0(\";`)`\\x22`f`a`w`b`p`j`0`/`r`k`.`o`c`.`t`s`u`r`t`g`i`b`\\x22" ascii
    $s9  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aUSc0(\";`)`\\x22`P`T`T`H`L`M`X`.`2`L`M`X`S`M`\\x22`(`t`c`e`j`b`O`X" ascii
    $s10 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aUSc0(\"/`*`@` `}`;`)`4`r`A`M`a`(`8`b`M`G`a` `n`r`u`t`e`r`;`)`(`e`s" ascii
    $s11 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aUSc0(\";`)`\\x22`P`T`T`H`L`M`X`.`2`L`M`X`S`M`\\x22`(`t`c`e`j`b`O`X" ascii
    $s12 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aUSc0(\";`)`\\x22`q`j`s`v`b`/`m`o`c`.`e`r`a`p`s`i`h`s`.`o`m`e`d`\\x" ascii
    $s13 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aUSc0(\"\")), 1);" fullword ascii
    $s14 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aUSc0(\";`1`+`1`=`6`m`X`T`a` `r`a`v`;`)`\\x22`t`c`e`j`b`O`m`e`t`s`y" ascii
    $s15 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aUSc0(\"/`*`@` `}`;`9`j`T`a` `n`r`u`t`e`r`;`)`\\x22`\\x22`(`]`\\x22" ascii
    $s16 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aUSc0(\";`)`\\x22`f`a`w`b`p`j`0`/`r`k`.`o`c`.`t`s`u`r`t`g`i`b`\\x22" ascii
    $s17 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aUSc0(\";`\\x22`i`J`o`b`R`G`U`A`N`\\x22` `=` `4`l`X`W`a` `r`a`v` `;" ascii
    $s18 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aUSc0(\";`\\x22`/`\\x22`+`\\x22`/`\\x22`+`\\x22`:`\\x22`+`\\x22`p`" ascii
    $s19 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aUSc0(\";`)`\\x22`p`q`1`y`r`x`2`/`m`o`c`.`r`a`e`w`r`e`f`a`l`\\x22` " ascii
    $s20 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aUSc0(\";`2`o`L`Y`a` `+` `5`e`G`O`a`=`9`s`M`G`a` `r`a`v\")), 1);" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}