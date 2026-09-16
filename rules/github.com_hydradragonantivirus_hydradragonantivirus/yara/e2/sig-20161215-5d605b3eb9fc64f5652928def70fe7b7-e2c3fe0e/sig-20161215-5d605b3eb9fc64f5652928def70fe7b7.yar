rule sig_20161215_5d605b3eb9fc64f5652928def70fe7b7 {
  meta:
    description = "datamaliciousorder - file 20161215_5d605b3eb9fc64f5652928def70fe7b7.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "777024e53fab4d8827a726fb01be8c4acd35abc54ad30a852ebdf9f5ba7b8d6d"

  strings:
    $s1  = "function aFa3(aHUa1) {eval(\"/*@cc_on var aEy3 = new Date() @*/\");aEy3[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aEy3[\"getUTC" ascii
    $s2  = "function aFa3(aHUa1) {eval(\"/*@cc_on var aEy3 = new Date() @*/\");aEy3[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aEy3[\"getUTC" ascii
    $s3  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aFa3(\"/`*`@` `}`;`}`;`e`u`n`i`t`n`o`c`{` `)`e`(` `h`c`t`a`c`}`;`k`" ascii
    $s4  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aFa3(\"/`*`@` `}`;`1`a`U`H`a` `n`r`u`t`e`r`;`)`\\x22`\\x22`(`]`\\x2" ascii
    $s5  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aFa3(\";`\\x22`/`\\x22`+`\\x22`/`\\x22`+`\\x22`:`\\x22`+`\\x22`p`" ascii
    $s6  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aFa3(\";`)`\\x22`n`g`h`b`5`k`/`m`o`c`.`8`6`6`0`\\x22` `+` `5`n`Q`a`" ascii
    $s7  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aFa3(\"/`*`@` `}`;`1`a`U`H`a` `n`r`u`t`e`r`;`)`\\x22`\\x22`(`]`\\x2" ascii
    $s8  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aFa3(\";`\\x22`i`J`o`b`R`G`U`A`N`\\x22` `=` `4`j`S`F`a` `r`a`v` `;`" ascii
    $s9  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aFa3(\"\")), 1);" fullword ascii
    $s10 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aFa3(\"/`*`@` `}`;`)`(`e`s`o`l`c`.`1`d`S`C`a`;`)`2` `,`0`x`D`a`(`]`" ascii
    $s11 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aFa3(\";`\\x22`k`\\x22` `+` `\\x22`z`.`\\x22` `+` `1`z`Y`X`a`=`8`n`" ascii
    $s12 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aFa3(\";`)`(`y`a`r`r`A` `w`e`n` `=` `6`t`N`a` `r`a`v` ` ` ` \")), 1" ascii
    $s13 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aFa3(\";`)`\\x22`P`T`T`H`L`M`X`.`2`L`M`X`S`M`\\x22`(`t`c`e`j`b`O`X`" ascii
    $s14 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aFa3(\"/`*`@` `}`;`)`7`w`U`a`(`9`y`P`a` `n`r`u`t`e`r`;`)`(`e`s`o`l`" ascii
    $s15 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aFa3(\"}`;`h`t`a`P`t`r`o`h`S`.`1`u`N`Y`a` `n`r`u`t`e`r`;`)`8`n`Z`a`" ascii
    $s16 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aFa3(\";`)`\\x22`P`T`T`H`L`M`X`.`2`L`M`X`S`M`\\x22`(`t`c`e`j`b`O`X`" ascii
    $s17 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aFa3(\"/`*`@` `}`;`)`(`e`s`o`l`c`.`1`d`S`C`a`;`)`2` `,`0`x`D`a`(`]`" ascii
    $s18 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aFa3(\";`)`\\x22`u`t`j`i`d`g`s`/`m`o`c`.`b`o`j`l`e`g`n`a`.`w`w`w`" ascii
    $s19 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aFa3(\"/`*`@` `}`;`6`m`A`a` `n`r`u`t`e`r`;`}`;`]`h`t`g`n`e`l`.`6`i`" ascii
    $s20 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aFa3(\";`)`\\x22`u`t`j`i`d`g`s`/`m`o`c`.`b`o`j`l`e`g`n`a`.`w`w`w`" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}