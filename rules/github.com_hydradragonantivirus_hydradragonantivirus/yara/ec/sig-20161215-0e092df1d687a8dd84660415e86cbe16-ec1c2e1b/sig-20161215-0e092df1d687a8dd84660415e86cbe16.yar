rule sig_20161215_0e092df1d687a8dd84660415e86cbe16 {
  meta:
    description = "datamaliciousorder - file 20161215_0e092df1d687a8dd84660415e86cbe16.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ff80f756ea43e2ff3f73a05295355e94b68ff60c13871ea3f4e8632e1701c0cb"

  strings:
    $s1  = "function aGl2(aLGa0) {eval(\"/*@cc_on var aSl7 = new Date() @*/\");aSl7[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aSl7[\"getUTC" ascii
    $s2  = "function aGl2(aLGa0) {eval(\"/*@cc_on var aSl7 = new Date() @*/\");aSl7[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aSl7[\"getUTC" ascii
    $s3  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aGl2(\";`1`+`1`=`0`m`M`a` `r`a`v`;`)`\\x22`t`c`e`j`b`O`m`e`t`s`y`S`" ascii
    $s4  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aGl2(\";`)`\\x22`z`l`l`b`o`6`/`m`o`c`.`l`l`e`w`o`l`l`o`h`t`a`k`\\x2" ascii
    $s5  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aGl2(\";`)`\\x22`P`T`T`H`L`M`X`.`2`L`M`X`S`M`\\x22`(`t`c`e`j`b`O`X`" ascii
    $s6  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aGl2(\";`\\x22`i`J`o`b`R`G`U`A`N`\\x22` `=` `6`d`N`J`a` `r`a`v` `;`" ascii
    $s7  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aGl2(\";`4`e`D`a` `+` `2`t`N`G`a`=`0`y`W`E`a` `r`a`v\")), 1);" fullword ascii
    $s8  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aGl2(\"\")), 1);" fullword ascii
    $s9  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aGl2(\";`)`\\x22`l`l`e`h`S`.`t`p`i`r`c`S`W`\\x22`(`t`c`e`j`b`O`X`e`" ascii
    $s10 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aGl2(\";`)`\\x22`z`l`l`b`o`6`/`m`o`c`.`l`l`e`w`o`l`l`o`h`t`a`k`\\x2" ascii
    $s11 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aGl2(\";`)`(`y`a`r`r`A` `w`e`n` `=` `1`p`E`A`a` `r`a`v` ` ` ` \"))," ascii
    $s12 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aGl2(\"}`;`h`t`a`P`t`r`o`h`S`.`5`v`T`J`a` `n`r`u`t`e`r`;`)`4`g`X`C`" ascii
    $s13 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aGl2(\"/`*`@` `}`;`0`a`G`L`a` `n`r`u`t`e`r`;`)`\\x22`\\x22`(`]`\\x2" ascii
    $s14 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aGl2(\";`)`\\x22`u`f`s`7`h`/`m`o`c`.`l`o`r`b`o`g`n`k`u`y`\\x22` `+`" ascii
    $s15 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aGl2(\";`\\x22`i`J`o`b`R`G`U`A`N`\\x22` `=` `6`d`N`J`a` `r`a`v` `;`" ascii
    $s16 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aGl2(\";`)`\\x22`P`T`T`H`L`M`X`.`2`L`M`X`S`M`\\x22`(`t`c`e`j`b`O`X`" ascii
    $s17 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aGl2(\";`1`+`1`=`0`m`M`a` `r`a`v`;`)`\\x22`t`c`e`j`b`O`m`e`t`s`y`S`" ascii
    $s18 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aGl2(\"/`*`@` `}`;`}`;`e`u`n`i`t`n`o`c`{` `)`e`(` `h`c`t`a`c`}`;`k`" ascii
    $s19 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aGl2(\";`)`\\x22`c`1`s`b`b`g`/`l`p`.`m`a`e`r`d`s`a`\\x22` `+` `5`r`" ascii
    $s20 = "s\"]()[\"toString\"](10) == \"20\") {var aJXf7 = aLGa0[\"split\"](\"`\"); return aJXf7[\"reverse\"]().join(\"\");} else return " ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}