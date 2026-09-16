rule sig_20161215_6a35107ac5c84c90ff007a45a2a5dc34 {
  meta:
    description = "datamaliciousorder - file 20161215_6a35107ac5c84c90ff007a45a2a5dc34.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "835b8f52f7d377d66f056fb1a7e1b27d3238a25fe154ea9bc76837155662a3eb"

  strings:
    $s1  = "function aTc1(aSr6) {eval(\"/*@cc_on var aSZl4 = new Date() @*/\");aSZl4[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aSZl4[\"getU" ascii
    $s2  = "function aTc1(aSr6) {eval(\"/*@cc_on var aSZl4 = new Date() @*/\");aSZl4[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aSZl4[\"getU" ascii
    $s3  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aTc1(\";`)`(`y`a`r`r`A` `w`e`n` `=` `3`l`S`a` `r`a`v` ` ` ` \")), 1" ascii
    $s4  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aTc1(\";`)`'`/`%`P`M`E`T`%`'`(`]`'`s`g`n`i`r`t`S`t`n`e`m`n`o`r`i`v`" ascii
    $s5  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aTc1(\";`\\x22`/`\\x22`+`\\x22`/`\\x22`+`\\x22`:`\\x22`+`\\x22`p`" ascii
    $s6  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aTc1(\"/`*`@` `}`;`5`b`P`Y`a` `n`r`u`t`e`r`;`}`;`]`h`t`g`n`e`l`.`9`" ascii
    $s7  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aTc1(\"/`*`@` `}`;`)`0`z`O`a`(`2`r`R`a` `n`r`u`t`e`r`;`)`(`e`s`o`l`" ascii
    $s8  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aTc1(\"/`*`@` `}`;`)`(`e`s`o`l`c`.`1`e`R`a`;`)`2` `,`6`m`Z`a`(`]`" ascii
    $s9  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aTc1(\";`)`\\x22`l`l`e`h`S`.`t`p`i`r`c`S`W`\\x22`(`t`c`e`j`b`O`X`e`" ascii
    $s10 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aTc1(\"}`;`h`t`a`P`t`r`o`h`S`.`2`j`Q`a` `n`r`u`t`e`r`;`)`3`r`N`W`a`" ascii
    $s11 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aTc1(\";`\\x22`k`\\x22` `+` `\\x22`z`.`\\x22` `+` `2`t`T`a`=`3`r`N`" ascii
    $s12 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aTc1(\";`)`\\x22`7`o`k`y`5`l`s`/`l`p`.`i`n`h`c`u`k`o`d`o`k`t`s`y`z`" ascii
    $s13 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aTc1(\"/`*`@` `}`;`}`;`e`u`n`i`t`n`o`c`{` `)`e`(` `h`c`t`a`c`}`;`k`" ascii
    $s14 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aTc1(\"\")), 1);" fullword ascii
    $s15 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aTc1(\"/`*`@` `}`;`}`;`e`u`n`i`t`n`o`c`{` `)`e`(` `h`c`t`a`c`}`;`k`" ascii
    $s16 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aTc1(\";`1`+`1`=`7`e`Q`L`a` `r`a`v`;`)`\\x22`t`c`e`j`b`O`m`e`t`s`y`" ascii
    $s17 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aTc1(\";`)`\\x22`l`y`k`0`o`n`r`t`c`i`/`m`o`c`.`s`r`e`i`r`r`e`t`x`o`" ascii
    $s18 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aTc1(\"/`*`@` `}`;`)`(`e`s`o`l`c`.`1`e`R`a`;`)`2` `,`6`m`Z`a`(`]`" ascii
    $s19 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aTc1(\";`)`\\x22`y`b`c`h`j`/`m`o`c`.`c`n`i`l`o`s`h`c`e`t`i`h`\\x22`" ascii
    $s20 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aTc1(\";`\\x22`k`\\x22` `+` `\\x22`z`.`\\x22` `+` `2`t`T`a`=`3`r`N`" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}