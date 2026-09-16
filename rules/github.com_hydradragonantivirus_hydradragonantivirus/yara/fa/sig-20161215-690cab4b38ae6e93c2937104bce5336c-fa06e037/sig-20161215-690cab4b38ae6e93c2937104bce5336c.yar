rule sig_20161215_690cab4b38ae6e93c2937104bce5336c {
  meta:
    description = "datamaliciousorder - file 20161215_690cab4b38ae6e93c2937104bce5336c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "49edc0acaf311717d270b2226f875c21cb752642cabbc09cc08e29071c92f7bb"

  strings:
    $s1  = "function aCu7(aYm5) {eval(\"/*@cc_on var aWt8 = new Date() @*/\");aWt8[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aWt8[\"getUTCM" ascii
    $s2  = "function aCu7(aYm5) {eval(\"/*@cc_on var aWt8 = new Date() @*/\");aWt8[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aWt8[\"getUTCM" ascii
    $s3  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aCu7(\";`)`\\x22`f`m`u`o`f`0`7`9`n`/`m`o`c`.`s`e`c`i`v`r`e`s`8`r`l`" ascii
    $s4  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aCu7(\";`)`'`/`%`P`M`E`T`%`'`(`]`'`s`g`n`i`r`t`S`t`n`e`m`n`o`r`i`v`" ascii
    $s5  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aCu7(\";`\\x22`k`\\x22` `+` `\\x22`z`.`\\x22` `+` `4`x`N`a`=`9`x`L`" ascii
    $s6  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aCu7(\";`)`\\x22`x`x`1`p`l`e`n`v`d`/`m`o`c`.`t`s`s`e`w`-`a`d`n`a`f`" ascii
    $s7  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aCu7(\"/`*`@` `}`;`8`f`B`H`a` `n`r`u`t`e`r`;`}`;`)`7`e`I`C`a`(`]`" ascii
    $s8  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aCu7(\"/`*`@` `}`;`7`h`O`M`a` `n`r`u`t`e`r`;`}`;`]`h`t`g`n`e`l`.`4`" ascii
    $s9  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aCu7(\";`\\x22`/`\\x22`+`\\x22`/`\\x22`+`\\x22`:`\\x22`+`\\x22`p`" ascii
    $s10 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aCu7(\"/`*`@` `}`;`8`f`B`H`a` `n`r`u`t`e`r`;`}`;`)`7`e`I`C`a`(`]`" ascii
    $s11 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aCu7(\";`)`\\x22`l`l`e`h`S`.`t`p`i`r`c`S`W`\\x22`(`t`c`e`j`b`O`X`e`" ascii
    $s12 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aCu7(\";`)`\\x22`b`4`b`f`e`a`w`m`/`u`a`.`m`o`c`.`r`e`d`i`s`n`i`l`e`" ascii
    $s13 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aCu7(\"}`;`h`t`a`P`t`r`o`h`S`.`6`f`D`a` `n`r`u`t`e`r`;`)`9`x`L`a`(`" ascii
    $s14 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aCu7(\"/`*`@` `}`;`5`m`Y`a` `n`r`u`t`e`r`;`)`\\x22`\\x22`(`]`\\x22`" ascii
    $s15 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aCu7(\";`1`+`1`=`7`t`B`O`a` `r`a`v`;`)`\\x22`t`c`e`j`b`O`m`e`t`s`y`" ascii
    $s16 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aCu7(\"/`*`@` `}`;`5`m`Y`a` `n`r`u`t`e`r`;`)`\\x22`\\x22`(`]`\\x22`" ascii
    $s17 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aCu7(\";`)`\\x22`h`k`m`s`y`2`4`b`t`f`/`t`e`n`.`u`t`n`a`u`h`c`\\x22`" ascii
    $s18 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aCu7(\"/`*`@` `}`;`)`7`q`X`a`(`6`f`O`a` `n`r`u`t`e`r`;`)`(`e`s`o`l`" ascii
    $s19 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aCu7(\";`)`(`y`a`r`r`A` `w`e`n` `=` `2`s`L`a` `r`a`v` ` ` ` \")), 1" ascii
    $s20 = "\"]()[\"toString\"](10) == \"20\") {var aHBf8 = aYm5[\"split\"](\"`\"); return aHBf8[\"reverse\"]().join(\"\");} else return \"" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}