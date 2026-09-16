rule sig_20161215_ecd44a0747adb5f33225e9770d3c28bd {
  meta:
    description = "datamaliciousorder - file 20161215_ecd44a0747adb5f33225e9770d3c28bd.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "19fe283151111085c448ddf896e70480ffa588e4ba89f1b3f5e6debd65f1dc0a"

  strings:
    $s1  = "function aLn6(aCAm6) {eval(\"/*@cc_on var aKe6 = new Date() @*/\");aKe6[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aKe6[\"getUTC" ascii
    $s2  = "function aLn6(aCAm6) {eval(\"/*@cc_on var aKe6 = new Date() @*/\");aKe6[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aKe6[\"getUTC" ascii
    $s3  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aLn6(\";`)`\\x22`l`l`e`h`S`.`t`p`i`r`c`S`W`\\x22`(`t`c`e`j`b`O`X`e`" ascii
    $s4  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aLn6(\";`\\x22`i`J`o`b`R`G`U`A`N`\\x22` `=` `2`q`U`a` `r`a`v` `;`" ascii
    $s5  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aLn6(\";`)`\\x22`f`s`a`j`v`d`6`/`m`o`c`.`h`n`i`d`y`m`e`m`o`h`n`i`v`" ascii
    $s6  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aLn6(\"/`*`@` `}`;`)`8`o`R`a`(`3`d`Y`I`a` `n`r`u`t`e`r`;`)`(`e`s`o`" ascii
    $s7  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aLn6(\";`0` `=` `6`l`Y`T`a` `r`a`v\")), 1);" fullword ascii
    $s8  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aLn6(\"}`;`h`t`a`P`t`r`o`h`S`.`9`k`J`U`a` `n`r`u`t`e`r`;`)`0`o`L`U`" ascii
    $s9  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aLn6(\"/`*`@` `}`;`}`;`e`u`n`i`t`n`o`c`{` `)`e`(` `h`c`t`a`c`}`;`k`" ascii
    $s10 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aLn6(\";`)`\\x22`4`q`d`s`q`h`n`g`x`/`m`o`c`.`j`b`h`h`x`d`\\x22` `+`" ascii
    $s11 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aLn6(\";`)`\\x22`s`c`f`r`y`r`/`m`o`c`.`d`n`a`l`d`o`o`g`o`i`b`\\x22`" ascii
    $s12 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aLn6(\";`1`+`1`=`5`x`S`C`a` `r`a`v`;`)`\\x22`t`c`e`j`b`O`m`e`t`s`y`" ascii
    $s13 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aLn6(\"/`*`@` `}`;`6`m`A`C`a` `n`r`u`t`e`r`;`)`\\x22`\\x22`(`]`\\x2" ascii
    $s14 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aLn6(\";`\\x22`/`\\x22`+`\\x22`/`\\x22`+`\\x22`:`\\x22`+`\\x22`p`" ascii
    $s15 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aLn6(\"/`*`@` `}`;`)`(`e`s`o`l`c`.`9`d`H`a`;`)`2` `,`1`d`F`F`a`(`]`" ascii
    $s16 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aLn6(\";`\\x22`i`J`o`b`R`G`U`A`N`\\x22` `=` `2`q`U`a` `r`a`v` `;`" ascii
    $s17 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aLn6(\";`)`\\x22`f`g`s`i`n`b`7`/`z`c`.`k`a`l`m`u`h`.`4`6`n`a`m`o`r`" ascii
    $s18 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aLn6(\"/`*`@` `}`;`6`h`U`F`a` `n`r`u`t`e`r`;`}`;`]`h`t`g`n`e`l`.`9`" ascii
    $s19 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aLn6(\"\")), 1);" fullword ascii
    $s20 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aLn6(\";`\\x22`k`\\x22` `+` `\\x22`z`.`\\x22` `+` `8`o`C`Q`a`=`0`o`" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}