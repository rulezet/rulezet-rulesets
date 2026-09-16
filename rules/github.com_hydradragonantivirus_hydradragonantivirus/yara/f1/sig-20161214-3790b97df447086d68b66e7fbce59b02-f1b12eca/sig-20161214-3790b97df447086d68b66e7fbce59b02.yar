rule sig_20161214_3790b97df447086d68b66e7fbce59b02 {
  meta:
    description = "datamaliciousorder - file 20161214_3790b97df447086d68b66e7fbce59b02.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "dbacac67f734e75b90d9f49ae3cf4f433f476083d7aabddc065ae58fc69dd532"

  strings:
    $s1  = "function aXTj7(aHu9) {eval(\"/*@cc_on var aHAr2 = new Date() @*/\");aHAr2[\"setUTCSeconds\"](\"0\", \"20\");if (aHAr2.getUTCMill" ascii
    $s2  = "function aXTj7(aHu9) {eval(\"/*@cc_on var aHAr2 = new Date() @*/\");aHAr2[\"setUTCSeconds\"](\"0\", \"20\");if (aHAr2.getUTCMill" ascii
    $s3  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aXTj7(\"/`*`@` `}`;`)`(`e`s`o`l`c`.`1`j`U`T`a`;`)`2` `,`0`p`V`a`(`]" ascii
    $s4  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aXTj7(\";`)`\\x22`f`m`u`o`f`0`7`9`n`/`m`o`c`.`s`e`c`i`v`r`e`s`8`r`l" ascii
    $s5  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aXTj7(\";`)`\\x22`a`g`9`d`2`h`6`b`i`k`/`n`c`.`3`2`1`d`y`f`\\x22` `+" ascii
    $s6  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aXTj7(\";`)`\\x22`b`4`b`f`e`a`w`m`/`u`a`.`m`o`c`.`r`e`d`i`s`n`i`l`e" ascii
    $s7  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aXTj7(\";`0`x`Q`a` `+` `9`d`X`D`a`=`6`l`V`a` `r`a`v\")), 1);" fullword ascii
    $s8  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aXTj7(\";`)`\\x22`a`g`9`d`2`h`6`b`i`k`/`n`c`.`3`2`1`d`y`f`\\x22` `+" ascii
    $s9  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aXTj7(\";`)`\\x22`l`l`e`h`S`.`t`p`i`r`c`S`W`\\x22`(`t`c`e`j`b`O`X`e" ascii
    $s10 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aXTj7(\";`)`\\x22`s`x`t`r`w`o`i`l`/`t`p`.`k`a`e`p`s`u`o`y`\\x22` `+" ascii
    $s11 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aXTj7(\";`)`\\x22`b`4`b`f`e`a`w`m`/`u`a`.`m`o`c`.`r`e`d`i`s`n`i`l`e" ascii
    $s12 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aXTj7(\";`)`'`/`%`P`M`E`T`%`'`(`]`'`s`g`n`i`r`t`S`t`n`e`m`n`o`r`i`v" ascii
    $s13 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aXTj7(\"/`*`@` `}`;`9`u`H`a` `n`r`u`t`e`r`;`)`\\x22`\\x22`(`]`\\x22" ascii
    $s14 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aXTj7(\";`)`'`/`%`P`M`E`T`%`'`(`]`'`s`g`n`i`r`t`S`t`n`e`m`n`o`r`i`v" ascii
    $s15 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aXTj7(\";`0` `=` `5`y`M`D`a` `r`a`v\")), 1);" fullword ascii
    $s16 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aXTj7(\"/`*`@` `}`;`}`;`e`u`n`i`t`n`o`c`{` `)`e`(` `h`c`t`a`c`}`;`k" ascii
    $s17 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aXTj7(\"/`*`@` `}`;`6`g`V`M`a` `n`r`u`t`e`r`;`}`;`)`9`o`T`V`a`(`]`" ascii
    $s18 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aXTj7(\"/`*`@` `}`;`}`;`e`u`n`i`t`n`o`c`{` `)`e`(` `h`c`t`a`c`}`;`k" ascii
    $s19 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aXTj7(\";`)`\\x22`a`c`4`e`q`k`/`m`o`c`.`8`1`3`x`t`\\x22` `+` `9`t`E" ascii
    $s20 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aXTj7(\"}`;`h`t`a`P`t`r`o`h`S`.`9`q`A`K`a` `n`r`u`t`e`r`;`)`4`d`A`a" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}