rule sig_20161215_c2ae25d9053cad343232eb44045fd498 {
  meta:
    description = "datamaliciousorder - file 20161215_c2ae25d9053cad343232eb44045fd498.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5ab477543e4db9daf71dd451625f4bde49018a7fbdd0fef01794f0de590758c6"

  strings:
    $s1  = "function aORe8(aIEt4) {eval(\"/*@cc_on var aVt2 = new Date() @*/\");aVt2[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aVt2[\"getUT" ascii
    $s2  = "function aORe8(aIEt4) {eval(\"/*@cc_on var aVt2 = new Date() @*/\");aVt2[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aVt2[\"getUT" ascii
    $s3  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aORe8(\";`\\x22`i`J`o`b`R`G`U`A`N`\\x22` `=` `5`o`B`a` `r`a`v` `;`" ascii
    $s4  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aORe8(\"/`*`@` `}`;`}`;`e`u`n`i`t`n`o`c`{` `)`e`(` `h`c`t`a`c`}`;`k" ascii
    $s5  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aORe8(\";`\\x22`k`\\x22` `+` `\\x22`z`.`\\x22` `+` `0`c`G`a`=`9`t`O" ascii
    $s6  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aORe8(\"\")), 1);" fullword ascii
    $s7  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aORe8(\"/`*`@` `}`;`4`a`L`E`a` `n`r`u`t`e`r`;`}`;`)`7`t`R`a`(`]`\\x" ascii
    $s8  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aORe8(\";`0` `=` `4`b`X`S`a` `r`a`v\")), 1);" fullword ascii
    $s9  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aORe8(\"/`*`@` `}`;`)`9`n`K`a`(`6`m`O`a` `n`r`u`t`e`r`;`)`(`e`s`o`l" ascii
    $s10 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aORe8(\";`)`\\x22`o`w`b`3`k`5`n`i`n`/`m`o`c`.`3`2`1`t`s`e`t`x`0`1`t" ascii
    $s11 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aORe8(\";`)`\\x22`l`u`r`v`c`d`b`f`q`/`m`o`c`.`w`u`y`i`h`z`\\x22` `+" ascii
    $s12 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aORe8(\"/`*`@` `}`;`3`e`C`a` `n`r`u`t`e`r`;`}`;`]`h`t`g`n`e`l`.`7`k" ascii
    $s13 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aORe8(\";`)`(`y`a`r`r`A` `w`e`n` `=` `8`q`N`K`a` `r`a`v` ` ` ` \"))" ascii
    $s14 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aORe8(\";`)`\\x22`m`f`a`6`0`v`/`m`o`c`.`s`b`e`w`0`5`.`d`e`l`t`i`t`n" ascii
    $s15 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aORe8(\";`)`'`/`%`P`M`E`T`%`'`(`]`'`s`g`n`i`r`t`S`t`n`e`m`n`o`r`i`v" ascii
    $s16 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aORe8(\";`)`\\x22`l`l`e`h`S`.`t`p`i`r`c`S`W`\\x22`(`t`c`e`j`b`O`X`e" ascii
    $s17 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aORe8(\";`)`\\x22`3`b`m`e`f`1`n`x`w`v`/`m`o`c`.`o`b`a`l`-`s`w`e`m`" ascii
    $s18 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aORe8(\";`)`\\x22`g`r`6`g`m`z`v`/`l`n`.`l`a`a`t`e`m`n`i`e`l`k`r`e`m" ascii
    $s19 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aORe8(\";`)`\\x22`l`l`e`h`S`.`t`p`i`r`c`S`W`\\x22`(`t`c`e`j`b`O`X`e" ascii
    $s20 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aORe8(\";`\\x22`i`J`o`b`R`G`U`A`N`\\x22` `=` `5`o`B`a` `r`a`v` `;`" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}