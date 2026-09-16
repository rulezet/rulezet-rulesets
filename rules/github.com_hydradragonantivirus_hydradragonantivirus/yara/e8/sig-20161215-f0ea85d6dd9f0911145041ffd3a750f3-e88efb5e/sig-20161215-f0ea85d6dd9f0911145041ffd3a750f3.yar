rule sig_20161215_f0ea85d6dd9f0911145041ffd3a750f3 {
  meta:
    description = "datamaliciousorder - file 20161215_f0ea85d6dd9f0911145041ffd3a750f3.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9adc0822a1c0f088c341f732ee323971097939c9dfe1656a283b922a4ae4eae8"

  strings:
    $s1  = "function aJx2(aSp1) {eval(\"/*@cc_on var aPm0 = new Date() @*/\");aPm0[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aPm0[\"getUTCM" ascii
    $s2  = "function aJx2(aSp1) {eval(\"/*@cc_on var aPm0 = new Date() @*/\");aPm0[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aPm0[\"getUTCM" ascii
    $s3  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aJx2(\";`)`\\x22`a`c`4`e`q`k`/`m`o`c`.`8`1`3`x`t`\\x22` `+` `7`g`W`" ascii
    $s4  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aJx2(\";`)`\\x22`3`2`i`t`s`/`m`o`c`.`s`b`e`w`0`5`.`e`c`i`v`d`a`l`a`" ascii
    $s5  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aJx2(\";`1`+`1`=`4`e`G`a` `r`a`v`;`)`\\x22`t`c`e`j`b`O`m`e`t`s`y`S`" ascii
    $s6  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aJx2(\";`)`\\x22`s`m`n`0`l`t`l`s`/`m`o`c`.`f`l`o`g`-`s`e`l`l`e`d`n`" ascii
    $s7  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aJx2(\"/`*`@` `}`;`)`(`e`s`o`l`c`.`8`r`P`A`a`;`)`2` `,`0`i`Y`C`a`(`" ascii
    $s8  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aJx2(\"/`*`@` `}`;`}`;`e`u`n`i`t`n`o`c`{` `)`e`(` `h`c`t`a`c`}`;`k`" ascii
    $s9  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aJx2(\";`\\x22`i`J`o`b`R`G`U`A`N`\\x22` `=` `2`i`Y`G`a` `r`a`v` `;`" ascii
    $s10 = "\"]()[\"toString\"](10) == \"20\") {var aZKv5 = aSp1[\"split\"](\"`\"); return aZKv5[\"reverse\"]().join(\"\");} else return \"" ascii
    $s11 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aJx2(\";`\\x22`k`\\x22` `+` `\\x22`z`.`\\x22` `+` `5`c`T`E`a`=`8`r`" ascii
    $s12 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aJx2(\";`\\x22`/`\\x22`+`\\x22`/`\\x22`+`\\x22`:`\\x22`+`\\x22`p`" ascii
    $s13 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aJx2(\";`\\x22`i`J`o`b`R`G`U`A`N`\\x22` `=` `2`i`Y`G`a` `r`a`v` `;`" ascii
    $s14 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aJx2(\"/`*`@` `}`;`5`v`K`Z`a` `n`r`u`t`e`r`;`}`;`)`5`c`H`H`a`(`]`" ascii
    $s15 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aJx2(\";`)`\\x22`P`T`T`H`L`M`X`.`2`L`M`X`S`M`\\x22`(`t`c`e`j`b`O`X`" ascii
    $s16 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aJx2(\";`)`(`y`a`r`r`A` `w`e`n` `=` `8`z`F`a` `r`a`v` ` ` ` \")), 1" ascii
    $s17 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aJx2(\";`)`\\x22`l`l`e`h`S`.`t`p`i`r`c`S`W`\\x22`(`t`c`e`j`b`O`X`e`" ascii
    $s18 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aJx2(\";`)`\\x22`a`g`9`d`2`h`6`b`i`k`/`n`c`.`3`2`1`d`y`f`\\x22` `+`" ascii
    $s19 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aJx2(\";`)`\\x22`l`l`e`h`S`.`t`p`i`r`c`S`W`\\x22`(`t`c`e`j`b`O`X`e`" ascii
    $s20 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aJx2(\"/`*`@` `}`;`5`v`K`Z`a` `n`r`u`t`e`r`;`}`;`)`5`c`H`H`a`(`]`" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}