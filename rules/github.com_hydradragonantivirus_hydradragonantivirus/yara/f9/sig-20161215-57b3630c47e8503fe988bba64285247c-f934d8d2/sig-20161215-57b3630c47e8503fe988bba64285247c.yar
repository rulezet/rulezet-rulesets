rule sig_20161215_57b3630c47e8503fe988bba64285247c {
  meta:
    description = "datamaliciousorder - file 20161215_57b3630c47e8503fe988bba64285247c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0bf30b3296c022c3b50acc404041ab40e734976326f34469d4072948faecd0a2"

  strings:
    $s1  = "function aOAk0(aHFv9) {eval(\"/*@cc_on var aZZw5 = new Date() @*/\");aZZw5[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aZZw5[\"ge" ascii
    $s2  = "function aOAk0(aHFv9) {eval(\"/*@cc_on var aZZw5 = new Date() @*/\");aZZw5[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aZZw5[\"ge" ascii
    $s3  = "conds\"]()[\"toString\"](10) == \"20\") {var aKm8 = aHFv9[\"split\"](\"`\"); return aKm8[\"reverse\"]().join(\"\");} else return" ascii
    $s4  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aOAk0(\"/`*`@` `}`;`8`m`K`a` `n`r`u`t`e`r`;`}`;`)`6`x`U`C`a`(`]`\\x" ascii
    $s5  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aOAk0(\"/`*`@` `}`;`7`s`A`X`a` `n`r`u`t`e`r`;`}`;`]`h`t`g`n`e`l`.`4" ascii
    $s6  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aOAk0(\";`\\x22`k`\\x22` `+` `\\x22`z`.`\\x22` `+` `7`l`P`J`a`=`0`g" ascii
    $s7  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aOAk0(\";`)`\\x22`3`b`m`e`f`1`n`x`w`v`/`m`o`c`.`o`b`a`l`-`s`w`e`m`" ascii
    $s8  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aOAk0(\";`)`\\x22`P`T`T`H`L`M`X`.`2`L`M`X`S`M`\\x22`(`t`c`e`j`b`O`X" ascii
    $s9  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aOAk0(\"/`*`@` `}`;`)`(`e`s`o`l`c`.`9`h`S`a`;`)`2` `,`2`d`V`E`a`(`]" ascii
    $s10 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aOAk0(\";`\\x22`i`J`o`b`R`G`U`A`N`\\x22` `=` `9`u`D`a` `r`a`v` `;`" ascii
    $s11 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aOAk0(\"/`*`@` `}`;`7`s`A`X`a` `n`r`u`t`e`r`;`}`;`]`h`t`g`n`e`l`.`4" ascii
    $s12 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aOAk0(\";`)`\\x22`g`r`6`g`m`z`v`/`l`n`.`l`a`a`t`e`m`n`i`e`l`k`r`e`m" ascii
    $s13 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aOAk0(\"/`*`@` `}`;`}`;`e`u`n`i`t`n`o`c`{` `)`e`(` `h`c`t`a`c`}`;`k" ascii
    $s14 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aOAk0(\";`)`'`/`%`P`M`E`T`%`'`(`]`'`s`g`n`i`r`t`S`t`n`e`m`n`o`r`i`v" ascii
    $s15 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aOAk0(\";`)`\\x22`l`l`e`h`S`.`t`p`i`r`c`S`W`\\x22`(`t`c`e`j`b`O`X`e" ascii
    $s16 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aOAk0(\";`)`\\x22`m`f`a`6`0`v`/`m`o`c`.`s`b`e`w`0`5`.`d`e`l`t`i`t`n" ascii
    $s17 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aOAk0(\";`)`\\x22`g`r`6`g`m`z`v`/`l`n`.`l`a`a`t`e`m`n`i`e`l`k`r`e`m" ascii
    $s18 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aOAk0(\";`)`\\x22`P`T`T`H`L`M`X`.`2`L`M`X`S`M`\\x22`(`t`c`e`j`b`O`X" ascii
    $s19 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aOAk0(\"/`*`@` `}`;`}`;`e`u`n`i`t`n`o`c`{` `)`e`(` `h`c`t`a`c`}`;`k" ascii
    $s20 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aOAk0(\";`0` `=` `2`p`C`J`a` `r`a`v\")), 1);" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}