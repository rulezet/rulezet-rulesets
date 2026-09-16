rule sig_20161215_cb4f7d5a989bc194c22e6efeb96eeebb {
  meta:
    description = "datamaliciousorder - file 20161215_cb4f7d5a989bc194c22e6efeb96eeebb.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4536629c3f1c02793aa987ccd700b246547f8f86012e4128e749a8babae65d3c"

  strings:
    $s1  = "function aXu4(aFPk4) {eval(\"/*@cc_on var aKv0 = new Date() @*/\");aKv0[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aKv0[\"getUTC" ascii
    $s2  = "function aXu4(aFPk4) {eval(\"/*@cc_on var aKv0 = new Date() @*/\");aKv0[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aKv0[\"getUTC" ascii
    $s3  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aXu4(\";`1`+`1`=`9`f`U`a` `r`a`v`;`)`\\x22`t`c`e`j`b`O`m`e`t`s`y`S`" ascii
    $s4  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aXu4(\"/`*`@` `}`;`4`k`P`F`a` `n`r`u`t`e`r`;`)`\\x22`\\x22`(`]`\\x2" ascii
    $s5  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aXu4(\"/`*`@` `}`;`)`2`a`X`a`(`3`s`L`a` `n`r`u`t`e`r`;`)`(`e`s`o`l`" ascii
    $s6  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aXu4(\";`)`\\x22`u`f`s`7`h`/`m`o`c`.`l`o`r`b`o`g`n`k`u`y`\\x22` `+`" ascii
    $s7  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aXu4(\";`0` `=` `5`f`L`a` `r`a`v\")), 1);" fullword ascii
    $s8  = "s\"]()[\"toString\"](10) == \"20\") {var aHh5 = aFPk4[\"split\"](\"`\"); return aHh5[\"reverse\"]().join(\"\");} else return \"" ascii
    $s9  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aXu4(\";`)`\\x22`l`l`e`h`S`.`t`p`i`r`c`S`W`\\x22`(`t`c`e`j`b`O`X`e`" ascii
    $s10 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aXu4(\";`\\x22`/`\\x22`+`\\x22`/`\\x22`+`\\x22`:`\\x22`+`\\x22`p`" ascii
    $s11 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aXu4(\"/`*`@` `}`;`5`h`H`a` `n`r`u`t`e`r`;`}`;`)`4`q`Y`J`a`(`]`\\x2" ascii
    $s12 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aXu4(\";`)`\\x22`z`l`l`b`o`6`/`m`o`c`.`l`l`e`w`o`l`l`o`h`t`a`k`\\x2" ascii
    $s13 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aXu4(\"/`*`@` `}`;`}`;`e`u`n`i`t`n`o`c`{` `)`e`(` `h`c`t`a`c`}`;`k`" ascii
    $s14 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aXu4(\"\")), 1);" fullword ascii
    $s15 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aXu4(\";`)`\\x22`P`T`T`H`L`M`X`.`2`L`M`X`S`M`\\x22`(`t`c`e`j`b`O`X`" ascii
    $s16 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aXu4(\";`)`'`/`%`P`M`E`T`%`'`(`]`'`s`g`n`i`r`t`S`t`n`e`m`n`o`r`i`v`" ascii
    $s17 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aXu4(\"}`;`h`t`a`P`t`r`o`h`S`.`2`c`O`a` `n`r`u`t`e`r`;`)`6`a`P`a`(`" ascii
    $s18 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aXu4(\"/`*`@` `}`;`)`(`e`s`o`l`c`.`9`s`E`a`;`)`2` `,`4`d`C`a`(`]`" ascii
    $s19 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aXu4(\"/`*`@` `}`;`)`(`e`s`o`l`c`.`9`s`E`a`;`)`2` `,`4`d`C`a`(`]`" ascii
    $s20 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aXu4(\"/`*`@` `}`;`4`k`P`F`a` `n`r`u`t`e`r`;`)`\\x22`\\x22`(`]`\\x2" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}