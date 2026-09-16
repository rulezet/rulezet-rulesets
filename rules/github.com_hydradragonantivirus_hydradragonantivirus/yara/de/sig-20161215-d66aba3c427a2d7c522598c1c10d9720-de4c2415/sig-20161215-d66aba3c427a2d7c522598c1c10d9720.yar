rule sig_20161215_d66aba3c427a2d7c522598c1c10d9720 {
  meta:
    description = "datamaliciousorder - file 20161215_d66aba3c427a2d7c522598c1c10d9720.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "16dc225e466b7db7f93cff2984a1e7a588ed972539bb3dca13d49ddc64970176"

  strings:
    $s1  = "function aZy5(aDm4) {eval(\"/*@cc_on var aWf0 = new Date() @*/\");aWf0[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aWf0[\"getUTCM" ascii
    $s2  = "function aZy5(aDm4) {eval(\"/*@cc_on var aWf0 = new Date() @*/\");aWf0[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aWf0[\"getUTCM" ascii
    $s3  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aZy5(\";`1`+`1`=`9`x`K`Z`a` `r`a`v`;`)`\\x22`t`c`e`j`b`O`m`e`t`s`y`" ascii
    $s4  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aZy5(\";`)`(`y`a`r`r`A` `w`e`n` `=` `2`v`Y`S`a` `r`a`v` ` ` ` \"))," ascii
    $s5  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aZy5(\";`4`p`U`a` `+` `4`s`T`D`a`=`8`f`W`a` `r`a`v\")), 1);" fullword ascii
    $s6  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aZy5(\";`)`\\x22`n`z`i`c`m`h`2`m`/`m`o`c`.`p`a`s`a`k`n`a`k`a`t`a`" ascii
    $s7  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aZy5(\"}`;`h`t`a`P`t`r`o`h`S`.`1`p`Z`C`a` `n`r`u`t`e`r`;`)`5`o`B`U`" ascii
    $s8  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aZy5(\";`)`\\x22`n`z`i`c`m`h`2`m`/`m`o`c`.`p`a`s`a`k`n`a`k`a`t`a`" ascii
    $s9  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aZy5(\";`\\x22`/`\\x22`+`\\x22`/`\\x22`+`\\x22`:`\\x22`+`\\x22`p`" ascii
    $s10 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aZy5(\";`)`\\x22`P`T`T`H`L`M`X`.`2`L`M`X`S`M`\\x22`(`t`c`e`j`b`O`X`" ascii
    $s11 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aZy5(\";`)`\\x22`o`9`f`n`c`4`w`s`z`/`u`r`.`r`e`k`a`r`b`e`l`u`r`\\x2" ascii
    $s12 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aZy5(\";`)`\\x22`z`x`p`o`t`l`/`l`p`.`o`t`u`a`-`a`f`l`a`\\x22` `+` `" ascii
    $s13 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aZy5(\"/`*`@` `}`;`)`(`e`s`o`l`c`.`7`r`W`H`a`;`)`2` `,`1`j`H`a`(`]`" ascii
    $s14 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aZy5(\"/`*`@` `}`;`}`;`e`u`n`i`t`n`o`c`{` `)`e`(` `h`c`t`a`c`}`;`k`" ascii
    $s15 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aZy5(\";`)`\\x22`l`l`e`h`S`.`t`p`i`r`c`S`W`\\x22`(`t`c`e`j`b`O`X`e`" ascii
    $s16 = "\"]()[\"toString\"](10) == \"20\") {var aAf3 = aDm4[\"split\"](\"`\"); return aAf3[\"reverse\"]().join(\"\");} else return \"\";" ascii
    $s17 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aZy5(\";`)`'`/`%`P`M`E`T`%`'`(`]`'`s`g`n`i`r`t`S`t`n`e`m`n`o`r`i`v`" ascii
    $s18 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aZy5(\"/`*`@` `}`;`2`b`G`C`a` `n`r`u`t`e`r`;`}`;`]`h`t`g`n`e`l`.`1`" ascii
    $s19 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aZy5(\";`0` `=` `4`b`L`a` `r`a`v\")), 1);" fullword ascii
    $s20 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aZy5(\"/`*`@` `}`;`)`(`e`s`o`l`c`.`7`r`W`H`a`;`)`2` `,`1`j`H`a`(`]`" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}