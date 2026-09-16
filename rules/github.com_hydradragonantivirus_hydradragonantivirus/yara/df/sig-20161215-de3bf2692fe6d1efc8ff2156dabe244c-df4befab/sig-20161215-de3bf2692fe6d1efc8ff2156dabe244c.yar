rule sig_20161215_de3bf2692fe6d1efc8ff2156dabe244c {
  meta:
    description = "datamaliciousorder - file 20161215_de3bf2692fe6d1efc8ff2156dabe244c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c3dc810686f4004844cfd750248f3fe871ed28b3cf9170b523618a364ca002ee"

  strings:
    $s1  = "function aHm6(aXu1) {eval(\"/*@cc_on var aKHk9 = new Date() @*/\");aKHk9[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aKHk9[\"getU" ascii
    $s2  = "function aHm6(aXu1) {eval(\"/*@cc_on var aKHk9 = new Date() @*/\");aKHk9[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aKHk9[\"getU" ascii
    $s3  = "nds\"]()[\"toString\"](10) == \"20\") {var aAq7 = aXu1[\"split\"](\"`\"); return aAq7[\"reverse\"]().join(\"\");} else return \"" ascii
    $s4  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aHm6(\";`)`(`y`a`r`r`A` `w`e`n` `=` `0`m`L`I`a` `r`a`v` ` ` ` \"))," ascii
    $s5  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aHm6(\";`\\x22`/`\\x22`+`\\x22`/`\\x22`+`\\x22`:`\\x22`+`\\x22`p`" ascii
    $s6  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aHm6(\";`)`\\x22`z`c`x`t`e`w`v`e`6`/`z`i`b`.`e`r`o`c`i`n`u`m`m`o`c`" ascii
    $s7  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aHm6(\";`)`\\x22`l`n`t`i`u`8`6`/`k`u`.`o`c`.`t`a`a`w`\\x22` `+` `9`" ascii
    $s8  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aHm6(\";`)`\\x22`l`n`t`i`u`8`6`/`k`u`.`o`c`.`t`a`a`w`\\x22` `+` `9`" ascii
    $s9  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aHm6(\"/`*`@` `}`;`}`;`e`u`n`i`t`n`o`c`{` `)`e`(` `h`c`t`a`c`}`;`k`" ascii
    $s10 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aHm6(\";`5`g`H`X`a` `+` `4`s`G`B`a`=`4`z`M`V`a` `r`a`v\")), 1);" fullword ascii
    $s11 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aHm6(\";`\\x22`/`\\x22`+`\\x22`/`\\x22`+`\\x22`:`\\x22`+`\\x22`p`" ascii
    $s12 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aHm6(\";`)`\\x22`P`T`T`H`L`M`X`.`2`L`M`X`S`M`\\x22`(`t`c`e`j`b`O`X`" ascii
    $s13 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aHm6(\"/`*`@` `}`;`1`u`X`a` `n`r`u`t`e`r`;`)`\\x22`\\x22`(`]`\\x22`" ascii
    $s14 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aHm6(\"\")), 1);" fullword ascii
    $s15 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aHm6(\";`0` `=` `2`c`A`a` `r`a`v\")), 1);" fullword ascii
    $s16 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aHm6(\";`)`\\x22`f`u`g`j`e`/`m`o`c`.`a`w`a`n`i`k`o`-`o`n`i`s`a`c`" ascii
    $s17 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aHm6(\";`\\x22`i`J`o`b`R`G`U`A`N`\\x22` `=` `9`w`P`a` `r`a`v` `;`" ascii
    $s18 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aHm6(\";`)`\\x22`2`z`m`u`4`/`k`u`.`o`c`.`p`o`h`s`e`m`i`l`b`u`s`\\x2" ascii
    $s19 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aHm6(\"/`*`@` `}`;`)`(`e`s`o`l`c`.`2`y`X`Y`a`;`)`2` `,`1`f`N`U`a`(`" ascii
    $s20 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aHm6(\";`)`\\x22`c`o`9`o`e`e`/`n`i`.`e`l`t`t`u`h`s`-`b`e`w`\\x22` `" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}