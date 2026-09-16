rule sig_20161215_9fc077b8c6cb4af1de52a9dcf38620de {
  meta:
    description = "datamaliciousorder - file 20161215_9fc077b8c6cb4af1de52a9dcf38620de.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "00bbe1663909ca550be25b44273fb9e0bd670f1a2542852760f21f91247b8cda"

  strings:
    $s1  = "function aZSb5(aDb1) {eval(\"/*@cc_on var aDHl8 = new Date() @*/\");aDHl8[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aDHl8[\"get" ascii
    $s2  = "function aZSb5(aDb1) {eval(\"/*@cc_on var aDHl8 = new Date() @*/\");aDHl8[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aDHl8[\"get" ascii
    $s3  = "onds\"]()[\"toString\"](10) == \"20\") {var aHs2 = aDb1[\"split\"](\"`\"); return aHs2[\"reverse\"]().join(\"\");} else return " ascii
    $s4  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aZSb5(\";`\\x22`i`J`o`b`R`G`U`A`N`\\x22` `=` `6`q`S`U`a` `r`a`v` `;" ascii
    $s5  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aZSb5(\"/`*`@` `}`;`1`b`D`a` `n`r`u`t`e`r`;`)`\\x22`\\x22`(`]`\\x22" ascii
    $s6  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aZSb5(\"}`;`h`t`a`P`t`r`o`h`S`.`7`o`Q`a` `n`r`u`t`e`r`;`)`7`e`E`D`a" ascii
    $s7  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aZSb5(\";`\\x22`i`J`o`b`R`G`U`A`N`\\x22` `=` `6`q`S`U`a` `r`a`v` `;" ascii
    $s8  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aZSb5(\";`)`\\x22`e`e`u`n`p`t`e`a`e`f`/`m`o`c`.`o`y`u`o`s`u`o`s`.`t" ascii
    $s9  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aZSb5(\";`)`(`y`a`r`r`A` `w`e`n` `=` `8`s`Y`O`a` `r`a`v` ` ` ` \"))" ascii
    $s10 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aZSb5(\";`)`'`/`%`P`M`E`T`%`'`(`]`'`s`g`n`i`r`t`S`t`n`e`m`n`o`r`i`v" ascii
    $s11 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aZSb5(\";`)`\\x22`u`r`b`j`u`b`y`e`1`/`m`o`c`.`u`d`i`a`t`u`.`x`w`\\x" ascii
    $s12 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aZSb5(\";`2`c`X`a` `+` `9`p`O`Y`a`=`0`y`W`O`a` `r`a`v\")), 1);" fullword ascii
    $s13 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aZSb5(\";`)`'`/`%`P`M`E`T`%`'`(`]`'`s`g`n`i`r`t`S`t`n`e`m`n`o`r`i`v" ascii
    $s14 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aZSb5(\";`\\x22`k`\\x22` `+` `\\x22`z`.`\\x22` `+` `0`y`W`O`a`=`7`e" ascii
    $s15 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aZSb5(\"/`*`@` `}`;`2`s`H`a` `n`r`u`t`e`r`;`}`;`)`2`x`P`G`a`(`]`\\x" ascii
    $s16 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aZSb5(\";`)`\\x22`u`r`b`j`u`b`y`e`1`/`m`o`c`.`u`d`i`a`t`u`.`x`w`\\x" ascii
    $s17 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aZSb5(\"/`*`@` `}`;`)`(`e`s`o`l`c`.`7`d`F`a`;`)`2` `,`1`e`Z`a`(`]`" ascii
    $s18 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aZSb5(\";`\\x22`/`\\x22`+`\\x22`/`\\x22`+`\\x22`:`\\x22`+`\\x22`p`" ascii
    $s19 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aZSb5(\";`1`+`1`=`5`b`A`E`a` `r`a`v`;`)`\\x22`t`c`e`j`b`O`m`e`t`s`y" ascii
    $s20 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aZSb5(\"/`*`@` `}`;`)`9`b`Q`a`(`3`p`O`G`a` `n`r`u`t`e`r`;`)`(`e`s`o" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}