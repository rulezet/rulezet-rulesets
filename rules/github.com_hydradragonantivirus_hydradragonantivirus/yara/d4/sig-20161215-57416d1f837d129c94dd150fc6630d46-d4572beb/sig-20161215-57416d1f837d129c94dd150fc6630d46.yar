rule sig_20161215_57416d1f837d129c94dd150fc6630d46 {
  meta:
    description = "datamaliciousorder - file 20161215_57416d1f837d129c94dd150fc6630d46.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e97ca9e77944319ec3260f5aa1a664a4575bed5a5b2e08da0b802083fb1456b1"

  strings:
    $s1  = "function aPs1(aSv6) {eval(\"/*@cc_on var aTDd7 = new Date() @*/\");aTDd7[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aTDd7[\"getU" ascii
    $s2  = "function aPs1(aSv6) {eval(\"/*@cc_on var aTDd7 = new Date() @*/\");aTDd7[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aTDd7[\"getU" ascii
    $s3  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aPs1(\"/`*`@` `}`;`2`s`W`S`a` `n`r`u`t`e`r`;`}`;`]`h`t`g`n`e`l`.`4`" ascii
    $s4  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aPs1(\"/`*`@` `}`;`6`v`S`a` `n`r`u`t`e`r`;`)`\\x22`\\x22`(`]`\\x22`" ascii
    $s5  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aPs1(\";`1`+`1`=`0`j`W`V`a` `r`a`v`;`)`\\x22`t`c`e`j`b`O`m`e`t`s`y`" ascii
    $s6  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aPs1(\";`)`\\x22`3`2`i`t`s`/`m`o`c`.`s`b`e`w`0`5`.`e`c`i`v`d`a`l`a`" ascii
    $s7  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aPs1(\";`)`'`/`%`P`M`E`T`%`'`(`]`'`s`g`n`i`r`t`S`t`n`e`m`n`o`r`i`v`" ascii
    $s8  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aPs1(\";`)`\\x22`n`q`y`n`s`2`z`5`m`l`/`m`o`c`.`9`9`9`d`c`d`w`\\x22`" ascii
    $s9  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aPs1(\";`\\x22`/`\\x22`+`\\x22`/`\\x22`+`\\x22`:`\\x22`+`\\x22`p`" ascii
    $s10 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aPs1(\"/`*`@` `}`;`5`j`E`a` `n`r`u`t`e`r`;`}`;`)`0`z`B`a`(`]`\\x22`" ascii
    $s11 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aPs1(\"/`*`@` `}`;`5`j`E`a` `n`r`u`t`e`r`;`}`;`)`0`z`B`a`(`]`\\x22`" ascii
    $s12 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aPs1(\";`)`\\x22`u`z`o`j`v`p`1`d`l`/`m`o`c`.`c`f`j`l`w`z`\\x22` `+`" ascii
    $s13 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aPs1(\";`\\x22`i`J`o`b`R`G`U`A`N`\\x22` `=` `9`j`G`S`a` `r`a`v` `;`" ascii
    $s14 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aPs1(\";`0` `=` `8`v`C`H`a` `r`a`v\")), 1);" fullword ascii
    $s15 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aPs1(\";`)`\\x22`j`v`n`x`u`/`p`j`.`9`1`1`a`m`a`\\x22` `+` `4`j`M`N`" ascii
    $s16 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aPs1(\";`\\x22`k`\\x22` `+` `\\x22`z`.`\\x22` `+` `5`h`Y`a`=`5`y`M`" ascii
    $s17 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aPs1(\";`)`\\x22`l`l`e`h`S`.`t`p`i`r`c`S`W`\\x22`(`t`c`e`j`b`O`X`e`" ascii
    $s18 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aPs1(\"/`*`@` `}`;`6`v`S`a` `n`r`u`t`e`r`;`)`\\x22`\\x22`(`]`\\x22`" ascii
    $s19 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aPs1(\";`\\x22`/`\\x22`+`\\x22`/`\\x22`+`\\x22`:`\\x22`+`\\x22`p`" ascii
    $s20 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aPs1(\"/`*`@` `}`;`)`(`e`s`o`l`c`.`1`o`H`a`;`)`2` `,`3`m`B`a`(`]`" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}