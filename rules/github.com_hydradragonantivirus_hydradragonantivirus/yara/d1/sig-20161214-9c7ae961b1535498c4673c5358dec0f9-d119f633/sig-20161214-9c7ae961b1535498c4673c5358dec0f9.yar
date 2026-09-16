rule sig_20161214_9c7ae961b1535498c4673c5358dec0f9 {
  meta:
    description = "datamaliciousorder - file 20161214_9c7ae961b1535498c4673c5358dec0f9.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "730fef94a45beab0aaa54f5959e174fae48f498a4db39ae9fd31129dff10c8f2"

  strings:
    $s1  = "function aJe2(aHz4) {eval(\"/*@cc_on var aMf6 = new Date() @*/\");aMf6[\"setUTCSeconds\"](\"0\", \"20\");if (aMf6.getUTCMillisec" ascii
    $s2  = "function aJe2(aHz4) {eval(\"/*@cc_on var aMf6 = new Date() @*/\");aMf6[\"setUTCSeconds\"](\"0\", \"20\");if (aMf6.getUTCMillisec" ascii
    $s3  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aJe2(\";`\\x22`w`s`m`i`D`j`Z`K`q`8`y`2`l`w`m`3`5`J`v`f`i`i`M`f`s`m`" ascii
    $s4  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aJe2(\";`\\x22`/`\\x22`+`\\x22`/`\\x22`+`\\x22`:`\\x22`+`\\x22`p`" ascii
    $s5  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aJe2(\"/`*`@` `}`;`}`;`e`u`n`i`t`n`o`c`{` `)`e`(` `h`c`t`a`c`}`;`k`" ascii
    $s6  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aJe2(\"}`;`h`t`a`P`t`r`o`h`S`.`1`x`X`F`a` `n`r`u`t`e`r`;`)`7`i`S`a`" ascii
    $s7  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aJe2(\"/`*`@` `}`;`0`p`F`M`a` `n`r`u`t`e`r`;`}`;`]`h`t`g`n`e`l`.`6`" ascii
    $s8  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aJe2(\"/`*`@` `}`;`}`;`e`u`n`i`t`n`o`c`{` `)`e`(` `h`c`t`a`c`}`;`k`" ascii
    $s9  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aJe2(\";`)`'`/`%`P`M`E`T`%`'`(`]`'`s`g`n`i`r`t`S`t`n`e`m`n`o`r`i`v`" ascii
    $s10 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aJe2(\";`)`\\x22`m`a`1`q`z`z`4`/`l`n`.`e`d`o`h`t`e`m`k`n`a`l`s`\\x2" ascii
    $s11 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aJe2(\";`)`\\x22`h`4`u`t`k`h`5`/`o`r`.`n`i`z`a`g`a`m`q`.`e`n`u`a`c`" ascii
    $s12 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aJe2(\";`)`\\x22`P`T`T`H`L`M`X`.`2`L`M`X`S`M`\\x22`(`t`c`e`j`b`O`X`" ascii
    $s13 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aJe2(\";`\\x22`k`\\x22` `+` `\\x22`z`.`\\x22` `+` `2`y`M`K`a`=`7`i`" ascii
    $s14 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aJe2(\";`6`s`E`a` `+` `3`f`J`a`=`2`y`M`K`a` `r`a`v\")), 1);" fullword ascii
    $s15 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aJe2(\";`)`\\x22`h`4`u`t`k`h`5`/`o`r`.`n`i`z`a`g`a`m`q`.`e`n`u`a`c`" ascii
    $s16 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aJe2(\"/`*`@` `}`;`)`9`n`S`a`(`3`z`X`L`a` `n`r`u`t`e`r`;`)`(`e`s`o`" ascii
    $s17 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aJe2(\"/`*`@` `}`;`4`z`H`a` `n`r`u`t`e`r`;`)`\\x22`\\x22`(`]`\\x22`" ascii
    $s18 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aJe2(\";`)`\\x22`l`l`e`h`S`.`t`p`i`r`c`S`W`\\x22`(`t`c`e`j`b`O`X`e`" ascii
    $s19 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aJe2(\";`)`\\x22`m`a`1`q`z`z`4`/`l`n`.`e`d`o`h`t`e`m`k`n`a`l`s`\\x2" ascii
    $s20 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aJe2(\"/`*`@` `}`;`0`p`F`M`a` `n`r`u`t`e`r`;`}`;`]`h`t`g`n`e`l`.`6`" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}