rule sig_20161215_d2fe14f93cbe165b21dba854139b07ad {
  meta:
    description = "datamaliciousorder - file 20161215_d2fe14f93cbe165b21dba854139b07ad.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "949f3bfb626d22268e9953c3f3d3a367ef742df5704cf7a229373c2de8a53c59"

  strings:
    $s1  = "function aVQy1(aLu4) {eval(\"/*@cc_on var aYHh2 = new Date() @*/\");aYHh2[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aYHh2[\"get" ascii
    $s2  = "function aVQy1(aLu4) {eval(\"/*@cc_on var aYHh2 = new Date() @*/\");aYHh2[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aYHh2[\"get" ascii
    $s3  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aVQy1(\";`\\x22`/`\\x22`+`\\x22`/`\\x22`+`\\x22`:`\\x22`+`\\x22`p`" ascii
    $s4  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aVQy1(\";`)`'`/`%`P`M`E`T`%`'`(`]`'`s`g`n`i`r`t`S`t`n`e`m`n`o`r`i`v" ascii
    $s5  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aVQy1(\";`)`\\x22`c`g`o`m`v`a`k`4`t`/`n`c`.`k`r`o`w`t`a`\\x22` `+` " ascii
    $s6  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aVQy1(\"/`*`@` `}`;`4`u`L`a` `n`r`u`t`e`r`;`)`\\x22`\\x22`(`]`\\x22" ascii
    $s7  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aVQy1(\";`7`s`L`S`a` `+` `1`d`U`K`a`=`5`g`H`H`a` `r`a`v\")), 1);" fullword ascii
    $s8  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aVQy1(\"/`*`@` `}`;`5`t`G`U`a` `n`r`u`t`e`r`;`}`;`]`h`t`g`n`e`l`.`3" ascii
    $s9  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aVQy1(\";`)`\\x22`P`T`T`H`L`M`X`.`2`L`M`X`S`M`\\x22`(`t`c`e`j`b`O`X" ascii
    $s10 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aVQy1(\";`)`\\x22`4`q`d`s`q`h`n`g`x`/`m`o`c`.`j`b`h`h`x`d`\\x22` `+" ascii
    $s11 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aVQy1(\";`\\x22`/`\\x22`+`\\x22`/`\\x22`+`\\x22`:`\\x22`+`\\x22`p`" ascii
    $s12 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aVQy1(\"}`;`h`t`a`P`t`r`o`h`S`.`9`m`F`Z`a` `n`r`u`t`e`r`;`)`5`n`B`a" ascii
    $s13 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aVQy1(\";`)`\\x22`P`T`T`H`L`M`X`.`2`L`M`X`S`M`\\x22`(`t`c`e`j`b`O`X" ascii
    $s14 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aVQy1(\";`0` `=` `0`w`C`O`a` `r`a`v\")), 1);" fullword ascii
    $s15 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aVQy1(\"/`*`@` `}`;`5`t`G`U`a` `n`r`u`t`e`r`;`}`;`]`h`t`g`n`e`l`.`3" ascii
    $s16 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aVQy1(\"/`*`@` `}`;`)`(`e`s`o`l`c`.`9`f`D`a`;`)`2` `,`6`n`X`a`(`]`" ascii
    $s17 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aVQy1(\"/`*`@` `}`;`)`5`u`R`Z`a`(`4`o`B`N`a` `n`r`u`t`e`r`;`)`(`e`s" ascii
    $s18 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aVQy1(\";`)`\\x22`f`g`s`i`n`b`7`/`z`c`.`k`a`l`m`u`h`.`4`6`n`a`m`o`r" ascii
    $s19 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aVQy1(\"/`*`@` `}`;`4`u`L`a` `n`r`u`t`e`r`;`)`\\x22`\\x22`(`]`\\x22" ascii
    $s20 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aVQy1(\";`1`+`1`=`9`s`Z`a` `r`a`v`;`)`\\x22`t`c`e`j`b`O`m`e`t`s`y`S" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}