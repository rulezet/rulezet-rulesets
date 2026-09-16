rule sig_20161214_be14103ab63b41b76dc9317105dfd7cd {
  meta:
    description = "datamaliciousorder - file 20161214_be14103ab63b41b76dc9317105dfd7cd.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "faafe13c3c777c70fdc8899aaa04953673ea5702360e08d301b4783110e8a2d8"

  strings:
    $s1  = "function aWv6(aNDt7) {eval(\"/*@cc_on var aWNq5 = new Date() @*/\");aWNq5[\"setUTCSeconds\"](\"0\", \"20\");if (aWNq5.getUTCMill" ascii
    $s2  = "function aWv6(aNDt7) {eval(\"/*@cc_on var aWNq5 = new Date() @*/\");aWNq5[\"setUTCSeconds\"](\"0\", \"20\");if (aWNq5.getUTCMill" ascii
    $s3  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aWv6(\";`)`'`/`%`P`M`E`T`%`'`(`]`'`s`g`n`i`r`t`S`t`n`e`m`n`o`r`i`v`" ascii
    $s4  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aWv6(\"/`*`@` `}`;`)`9`n`I`Y`a`(`5`c`P`L`a` `n`r`u`t`e`r`;`)`(`e`s`" ascii
    $s5  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aWv6(\";`)`'`/`%`P`M`E`T`%`'`(`]`'`s`g`n`i`r`t`S`t`n`e`m`n`o`r`i`v`" ascii
    $s6  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aWv6(\"/`*`@` `}`;`6`g`C`T`a` `n`r`u`t`e`r`;`}`;`]`h`t`g`n`e`l`.`2`" ascii
    $s7  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aWv6(\"/`*`@` `}`;`0`c`B`a` `n`r`u`t`e`r`;`}`;`)`7`m`B`K`a`(`]`\\x2" ascii
    $s8  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aWv6(\";`)`\\x22`7`o`k`y`5`l`s`/`l`p`.`i`n`h`c`u`k`o`d`o`k`t`s`y`z`" ascii
    $s9  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aWv6(\";`\\x22`k`\\x22` `+` `\\x22`z`.`\\x22` `+` `3`k`H`a`=`9`c`K`" ascii
    $s10 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aWv6(\";`)`\\x22`7`w`1`o`y`d`/`m`o`c`.`n`g`i`s`e`d`m`e`r`a`u`q`s`.`" ascii
    $s11 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aWv6(\"/`*`@` `}`;`)`(`e`s`o`l`c`.`9`u`B`a`;`)`2` `,`8`k`P`a`(`]`" ascii
    $s12 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aWv6(\";`)`\\x22`l`l`e`h`S`.`t`p`i`r`c`S`W`\\x22`(`t`c`e`j`b`O`X`e`" ascii
    $s13 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aWv6(\"/`*`@` `}`;`)`(`e`s`o`l`c`.`9`u`B`a`;`)`2` `,`8`k`P`a`(`]`" ascii
    $s14 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aWv6(\"/`*`@` `}`;`}`;`e`u`n`i`t`n`o`c`{` `)`e`(` `h`c`t`a`c`}`;`k`" ascii
    $s15 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aWv6(\";`1`+`1`=`2`r`W`D`a` `r`a`v`;`)`\\x22`t`c`e`j`b`O`m`e`t`s`y`" ascii
    $s16 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aWv6(\";`)`\\x22`z`9`f`w`y`e`p`f`e`e`/`m`o`c`.`e`c`i`v`r`e`s`e`n`e`" ascii
    $s17 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aWv6(\";`)`\\x22`u`6`b`s`z`y`p`d`/`m`o`c`.`b`g`s`o`f`e`d`e`h`\\x22`" ascii
    $s18 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aWv6(\";`\\x22`w`s`m`i`D`j`Z`K`q`8`y`2`l`w`m`3`5`J`v`f`i`i`M`f`s`m`" ascii
    $s19 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aWv6(\";`5`j`R`E`a` `+` `2`n`V`a`=`3`k`H`a` `r`a`v\")), 1);" fullword ascii
    $s20 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aWv6(\"/`*`@` `}`;`0`c`B`a` `n`r`u`t`e`r`;`}`;`)`7`m`B`K`a`(`]`\\x2" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}