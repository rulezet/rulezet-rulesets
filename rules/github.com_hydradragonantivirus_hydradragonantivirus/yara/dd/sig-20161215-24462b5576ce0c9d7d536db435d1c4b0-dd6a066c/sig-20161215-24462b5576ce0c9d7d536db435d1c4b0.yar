rule sig_20161215_24462b5576ce0c9d7d536db435d1c4b0 {
  meta:
    description = "datamaliciousorder - file 20161215_24462b5576ce0c9d7d536db435d1c4b0.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c073d000ef9b12fd9985e04264f463b820b4b729e891407aa424fc076ac374c0"

  strings:
    $s1  = "function aLPd4(aGMw5) {eval(\"/*@cc_on var aGt7 = new Date() @*/\");aGt7[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aGt7[\"getUT" ascii
    $s2  = "function aLPd4(aGMw5) {eval(\"/*@cc_on var aGt7 = new Date() @*/\");aGt7[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aGt7[\"getUT" ascii
    $s3  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aLPd4(\"/`*`@` `}`;`5`w`M`G`a` `n`r`u`t`e`r`;`)`\\x22`\\x22`(`]`\\x" ascii
    $s4  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aLPd4(\";`)`\\x22`f`a`w`b`p`j`0`/`r`k`.`o`c`.`t`s`u`r`t`g`i`b`\\x22" ascii
    $s5  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aLPd4(\"/`*`@` `}`;`5`w`M`G`a` `n`r`u`t`e`r`;`)`\\x22`\\x22`(`]`\\x" ascii
    $s6  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aLPd4(\";`)`\\x22`v`q`n`m`f`0`/`m`o`c`.`s`o`t`o`h`p`o`z`\\x22` `+` " ascii
    $s7  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aLPd4(\";`)`\\x22`k`c`n`t`k`k`a`/`m`o`c`.`e`r`a`i`l`i`b`o`m`m`i`e`n" ascii
    $s8  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aLPd4(\"/`*`@` `}`;`)`(`e`s`o`l`c`.`6`e`L`a`;`)`2` `,`9`t`N`a`(`]`" ascii
    $s9  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aLPd4(\"}`;`h`t`a`P`t`r`o`h`S`.`9`p`W`U`a` `n`r`u`t`e`r`;`)`3`j`M`a" ascii
    $s10 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aLPd4(\";`)`\\x22`l`l`e`h`S`.`t`p`i`r`c`S`W`\\x22`(`t`c`e`j`b`O`X`e" ascii
    $s11 = "ds\"]()[\"toString\"](10) == \"20\") {var aLz8 = aGMw5[\"split\"](\"`\"); return aLz8[\"reverse\"]().join(\"\");} else return \"" ascii
    $s12 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aLPd4(\";`)`\\x22`v`q`n`m`f`0`/`m`o`c`.`s`o`t`o`h`p`o`z`\\x22` `+` " ascii
    $s13 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aLPd4(\"/`*`@` `}`;`8`z`L`a` `n`r`u`t`e`r`;`}`;`)`5`j`U`a`(`]`\\x22" ascii
    $s14 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aLPd4(\"/`*`@` `}`;`)`(`e`s`o`l`c`.`6`e`L`a`;`)`2` `,`9`t`N`a`(`]`" ascii
    $s15 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aLPd4(\";`)`\\x22`f`a`w`b`p`j`0`/`r`k`.`o`c`.`t`s`u`r`t`g`i`b`\\x22" ascii
    $s16 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aLPd4(\";`4`q`T`a` `+` `0`a`V`a`=`1`k`T`a` `r`a`v\")), 1);" fullword ascii
    $s17 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aLPd4(\";`\\x22`i`J`o`b`R`G`U`A`N`\\x22` `=` `4`v`Y`a` `r`a`v` `;`" ascii
    $s18 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aLPd4(\";`\\x22`k`\\x22` `+` `\\x22`z`.`\\x22` `+` `1`k`T`a`=`3`j`M" ascii
    $s19 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aLPd4(\"\")), 1);" fullword ascii
    $s20 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aLPd4(\";`)`\\x22`l`l`e`h`S`.`t`p`i`r`c`S`W`\\x22`(`t`c`e`j`b`O`X`e" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}