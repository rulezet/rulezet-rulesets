rule sig_20161215_b5843c12d90d66b52a4a6c7b72f791aa {
  meta:
    description = "datamaliciousorder - file 20161215_b5843c12d90d66b52a4a6c7b72f791aa.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f410778b44036b35bcd72cba7cdb0d6e6c3f81b0aa617d3f61e23141428974f4"

  strings:
    $s1  = "function aPl7(aXc5) {eval(\"/*@cc_on var aPf5 = new Date() @*/\");aPf5[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aPf5[\"getUTCM" ascii
    $s2  = "function aPl7(aXc5) {eval(\"/*@cc_on var aPf5 = new Date() @*/\");aPf5[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aPf5[\"getUTCM" ascii
    $s3  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aPl7(\";`\\x22`/`\\x22`+`\\x22`/`\\x22`+`\\x22`:`\\x22`+`\\x22`p`" ascii
    $s4  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aPl7(\";`)`\\x22`z`l`l`b`o`6`/`m`o`c`.`l`l`e`w`o`l`l`o`h`t`a`k`\\x2" ascii
    $s5  = "\"]()[\"toString\"](10) == \"20\") {var aITx9 = aXc5[\"split\"](\"`\"); return aITx9[\"reverse\"]().join(\"\");} else return \"" ascii
    $s6  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aPl7(\"/`*`@` `}`;`}`;`e`u`n`i`t`n`o`c`{` `)`e`(` `h`c`t`a`c`}`;`k`" ascii
    $s7  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aPl7(\";`0` `=` `1`k`D`a` `r`a`v\")), 1);" fullword ascii
    $s8  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aPl7(\";`4`f`X`a` `+` `7`e`P`J`a`=`5`a`D`R`a` `r`a`v\")), 1);" fullword ascii
    $s9  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aPl7(\"/`*`@` `}`;`9`y`B`P`a` `n`r`u`t`e`r`;`}`;`]`h`t`g`n`e`l`.`4`" ascii
    $s10 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aPl7(\"}`;`h`t`a`P`t`r`o`h`S`.`1`l`M`a` `n`r`u`t`e`r`;`)`3`w`G`a`(`" ascii
    $s11 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aPl7(\"/`*`@` `}`;`)`(`e`s`o`l`c`.`7`p`V`a`;`)`2` `,`2`o`X`a`(`]`" ascii
    $s12 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aPl7(\"}`;`h`t`a`P`t`r`o`h`S`.`1`l`M`a` `n`r`u`t`e`r`;`)`3`w`G`a`(`" ascii
    $s13 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aPl7(\";`\\x22`/`\\x22`+`\\x22`/`\\x22`+`\\x22`:`\\x22`+`\\x22`p`" ascii
    $s14 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aPl7(\"/`*`@` `}`;`)`(`e`s`o`l`c`.`7`p`V`a`;`)`2` `,`2`o`X`a`(`]`" ascii
    $s15 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aPl7(\"/`*`@` `}`;`)`5`d`Y`a`(`6`e`Q`W`a` `n`r`u`t`e`r`;`)`(`e`s`o`" ascii
    $s16 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aPl7(\";`)`\\x22`l`n`t`i`u`8`6`/`k`u`.`o`c`.`t`a`a`w`\\x22` `+` `0`" ascii
    $s17 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aPl7(\";`)`\\x22`P`T`T`H`L`M`X`.`2`L`M`X`S`M`\\x22`(`t`c`e`j`b`O`X`" ascii
    $s18 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aPl7(\";`)`\\x22`f`u`g`j`e`/`m`o`c`.`a`w`a`n`i`k`o`-`o`n`i`s`a`c`" ascii
    $s19 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aPl7(\";`)`\\x22`f`u`g`j`e`/`m`o`c`.`a`w`a`n`i`k`o`-`o`n`i`s`a`c`" ascii
    $s20 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aPl7(\"/`*`@` `}`;`9`x`T`I`a` `n`r`u`t`e`r`;`}`;`)`7`x`M`U`a`(`]`" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}