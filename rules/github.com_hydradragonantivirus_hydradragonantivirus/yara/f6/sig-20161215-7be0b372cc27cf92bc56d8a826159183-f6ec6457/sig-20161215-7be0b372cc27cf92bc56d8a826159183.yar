rule sig_20161215_7be0b372cc27cf92bc56d8a826159183 {
  meta:
    description = "datamaliciousorder - file 20161215_7be0b372cc27cf92bc56d8a826159183.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "df883e4914db78f44d10a561d6e602a1fb118bb08b1d3c0979a07e23700b046b"

  strings:
    $s1  = "function aLd2(aRq8) {eval(\"/*@cc_on var aRf7 = new Date() @*/\");aRf7[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aRf7[\"getUTCM" ascii
    $s2  = "function aLd2(aRq8) {eval(\"/*@cc_on var aRf7 = new Date() @*/\");aRf7[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aRf7[\"getUTCM" ascii
    $s3  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aLd2(\";`)`\\x22`f`g`s`i`n`b`7`/`z`c`.`k`a`l`m`u`h`.`4`6`n`a`m`o`r`" ascii
    $s4  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aLd2(\";`1`+`1`=`5`m`P`P`a` `r`a`v`;`)`\\x22`t`c`e`j`b`O`m`e`t`s`y`" ascii
    $s5  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aLd2(\";`\\x22`i`J`o`b`R`G`U`A`N`\\x22` `=` `3`r`E`a` `r`a`v` `;`" ascii
    $s6  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aLd2(\";`)`'`/`%`P`M`E`T`%`'`(`]`'`s`g`n`i`r`t`S`t`n`e`m`n`o`r`i`v`" ascii
    $s7  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aLd2(\"/`*`@` `}`;`)`8`b`V`O`a`(`0`p`Z`a` `n`r`u`t`e`r`;`)`(`e`s`o`" ascii
    $s8  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aLd2(\";`\\x22`i`J`o`b`R`G`U`A`N`\\x22` `=` `3`r`E`a` `r`a`v` `;`" ascii
    $s9  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aLd2(\"/`*`@` `}`;`8`n`R`W`a` `n`r`u`t`e`r`;`}`;`]`h`t`g`n`e`l`.`6`" ascii
    $s10 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aLd2(\";`)`\\x22`l`l`e`h`S`.`t`p`i`r`c`S`W`\\x22`(`t`c`e`j`b`O`X`e`" ascii
    $s11 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aLd2(\";`1`a`Q`a` `+` `3`m`V`a`=`8`h`S`a` `r`a`v\")), 1);" fullword ascii
    $s12 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aLd2(\"}`;`h`t`a`P`t`r`o`h`S`.`6`i`N`O`a` `n`r`u`t`e`r`;`)`0`f`Z`A`" ascii
    $s13 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aLd2(\";`0` `=` `5`j`M`M`a` `r`a`v\")), 1);" fullword ascii
    $s14 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aLd2(\"/`*`@` `}`;`0`n`I`D`a` `n`r`u`t`e`r`;`}`;`)`3`f`W`a`(`]`\\x2" ascii
    $s15 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aLd2(\"/`*`@` `}`;`)`8`b`V`O`a`(`0`p`Z`a` `n`r`u`t`e`r`;`)`(`e`s`o`" ascii
    $s16 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aLd2(\";`)`\\x22`f`g`s`i`n`b`7`/`z`c`.`k`a`l`m`u`h`.`4`6`n`a`m`o`r`" ascii
    $s17 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aLd2(\";`1`+`1`=`5`m`P`P`a` `r`a`v`;`)`\\x22`t`c`e`j`b`O`m`e`t`s`y`" ascii
    $s18 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aLd2(\";`)`\\x22`l`l`e`h`S`.`t`p`i`r`c`S`W`\\x22`(`t`c`e`j`b`O`X`e`" ascii
    $s19 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aLd2(\";`)`\\x22`c`g`o`m`v`a`k`4`t`/`n`c`.`k`r`o`w`t`a`\\x22` `+` `" ascii
    $s20 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aLd2(\";`)`'`/`%`P`M`E`T`%`'`(`]`'`s`g`n`i`r`t`S`t`n`e`m`n`o`r`i`v`" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}