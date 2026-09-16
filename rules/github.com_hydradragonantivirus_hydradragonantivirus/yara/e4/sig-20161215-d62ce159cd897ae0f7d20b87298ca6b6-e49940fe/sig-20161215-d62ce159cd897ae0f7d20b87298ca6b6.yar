rule sig_20161215_d62ce159cd897ae0f7d20b87298ca6b6 {
  meta:
    description = "datamaliciousorder - file 20161215_d62ce159cd897ae0f7d20b87298ca6b6.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f19346f77d7af5b8a617bd9c7f8e05f6d33b1d65b66b9f40418c27a103ad33aa"

  strings:
    $s1  = "function aCs0(aSDc1) {eval(\"/*@cc_on var aRGx4 = new Date() @*/\");aRGx4[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aRGx4[\"get" ascii
    $s2  = "function aCs0(aSDc1) {eval(\"/*@cc_on var aRGx4 = new Date() @*/\");aRGx4[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aRGx4[\"get" ascii
    $s3  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aCs0(\";`)`\\x22`4`x`p`s`u`s`c`n`/`m`o`c`.`s`b`e`w`0`5`.`d`e`l`t`i`" ascii
    $s4  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aCs0(\"/`*`@` `}`;`3`r`C`V`a` `n`r`u`t`e`r`;`}`;`]`h`t`g`n`e`l`.`0`" ascii
    $s5  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aCs0(\";`)`\\x22`g`r`f`q`w`x`k`p`/`m`o`c`.`s`b`e`w`0`5`.`k`o`o`b`" ascii
    $s6  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aCs0(\";`)`\\x22`0`8`v`i`r`u`g`j`m`/`m`o`c`.`s`y`b`u`s`\\x22` `+` `" ascii
    $s7  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aCs0(\";`)`\\x22`0`8`v`i`r`u`g`j`m`/`m`o`c`.`s`y`b`u`s`\\x22` `+` `" ascii
    $s8  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aCs0(\";`\\x22`i`J`o`b`R`G`U`A`N`\\x22` `=` `4`s`R`P`a` `r`a`v` `;`" ascii
    $s9  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aCs0(\";`\\x22`k`\\x22` `+` `\\x22`z`.`\\x22` `+` `9`i`M`a`=`6`a`S`" ascii
    $s10 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aCs0(\"/`*`@` `}`;`1`c`D`S`a` `n`r`u`t`e`r`;`)`\\x22`\\x22`(`]`\\x2" ascii
    $s11 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aCs0(\"/`*`@` `}`;`)`(`e`s`o`l`c`.`7`f`E`a`;`)`2` `,`3`v`R`L`a`(`]`" ascii
    $s12 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aCs0(\"/`*`@` `}`;`)`(`e`s`o`l`c`.`7`f`E`a`;`)`2` `,`3`v`R`L`a`(`]`" ascii
    $s13 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aCs0(\"/`*`@` `}`;`5`y`C`a` `n`r`u`t`e`r`;`}`;`)`2`g`U`a`(`]`\\x22`" ascii
    $s14 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aCs0(\"/`*`@` `}`;`1`c`D`S`a` `n`r`u`t`e`r`;`)`\\x22`\\x22`(`]`\\x2" ascii
    $s15 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aCs0(\";`)`\\x22`g`r`f`q`w`x`k`p`/`m`o`c`.`s`b`e`w`0`5`.`k`o`o`b`" ascii
    $s16 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aCs0(\"/`*`@` `}`;`)`7`w`Y`a`(`1`g`T`a` `n`r`u`t`e`r`;`)`(`e`s`o`l`" ascii
    $s17 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aCs0(\";`\\x22`/`\\x22`+`\\x22`/`\\x22`+`\\x22`:`\\x22`+`\\x22`p`" ascii
    $s18 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aCs0(\";`)`\\x22`4`x`p`s`u`s`c`n`/`m`o`c`.`s`b`e`w`0`5`.`d`e`l`t`i`" ascii
    $s19 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aCs0(\";`1`+`1`=`7`t`U`a` `r`a`v`;`)`\\x22`t`c`e`j`b`O`m`e`t`s`y`S`" ascii
    $s20 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aCs0(\"/`*`@` `}`;`)`7`w`Y`a`(`1`g`T`a` `n`r`u`t`e`r`;`)`(`e`s`o`l`" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}