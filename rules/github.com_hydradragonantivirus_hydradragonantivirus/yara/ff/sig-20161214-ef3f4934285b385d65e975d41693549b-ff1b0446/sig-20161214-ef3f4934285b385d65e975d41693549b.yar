rule sig_20161214_ef3f4934285b385d65e975d41693549b {
  meta:
    description = "datamaliciousorder - file 20161214_ef3f4934285b385d65e975d41693549b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2633d64fd9cebe90a6acc1d55d676465e5a5813a6b65236c1169708002f724b1"

  strings:
    $s1  = "function aGYz9(aBKw9) {eval(\"/*@cc_on var aUo9 = new Date() @*/\");aUo9[\"setUTCSeconds\"](\"0\", \"20\");if (aUo9.getUTCMillis" ascii
    $s2  = "function aGYz9(aBKw9) {eval(\"/*@cc_on var aUo9 = new Date() @*/\");aUo9[\"setUTCSeconds\"](\"0\", \"20\");if (aUo9.getUTCMillis" ascii
    $s3  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aGYz9(\";`)`\\x22`l`l`e`h`S`.`t`p`i`r`c`S`W`\\x22`(`t`c`e`j`b`O`X`e" ascii
    $s4  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aGYz9(\";`)`\\x22`m`a`1`q`z`z`4`/`l`n`.`e`d`o`h`t`e`m`k`n`a`l`s`\\x" ascii
    $s5  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aGYz9(\";`1`+`1`=`2`y`Z`R`a` `r`a`v`;`)`\\x22`t`c`e`j`b`O`m`e`t`s`y" ascii
    $s6  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aGYz9(\";`)`\\x22`f`u`g`j`e`/`m`o`c`.`a`w`a`n`i`k`o`-`o`n`i`s`a`c`" ascii
    $s7  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aGYz9(\";`)`'`/`%`P`M`E`T`%`'`(`]`'`s`g`n`i`r`t`S`t`n`e`m`n`o`r`i`v" ascii
    $s8  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aGYz9(\"/`*`@` `}`;`9`w`K`B`a` `n`r`u`t`e`r`;`)`\\x22`\\x22`(`]`\\x" ascii
    $s9  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aGYz9(\";`)`'`/`%`P`M`E`T`%`'`(`]`'`s`g`n`i`r`t`S`t`n`e`m`n`o`r`i`v" ascii
    $s10 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aGYz9(\"/`*`@` `}`;`}`;`e`u`n`i`t`n`o`c`{` `)`e`(` `h`c`t`a`c`}`;`k" ascii
    $s11 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aGYz9(\";`1`a`X`a` `+` `5`l`F`a`=`9`y`J`a` `r`a`v\")), 1);" fullword ascii
    $s12 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aGYz9(\";`)`\\x22`f`u`g`j`e`/`m`o`c`.`a`w`a`n`i`k`o`-`o`n`i`s`a`c`" ascii
    $s13 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aGYz9(\"/`*`@` `}`;`)`3`k`V`a`(`4`q`P`a` `n`r`u`t`e`r`;`)`(`e`s`o`l" ascii
    $s14 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aGYz9(\";`)`\\x22`g`i`d`d`1`/`u`r`.`o`n`i`j`y`m`.`8`8`c`i`l`o`r`c`" ascii
    $s15 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aGYz9(\";`\\x22`k`\\x22` `+` `\\x22`z`.`\\x22` `+` `9`y`J`a`=`3`i`P" ascii
    $s16 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aGYz9(\";`\\x22`w`s`m`i`D`j`Z`K`q`8`y`2`l`w`m`3`5`J`v`f`i`i`M`f`s`m" ascii
    $s17 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aGYz9(\";`0` `=` `1`x`O`S`a` `r`a`v\")), 1);" fullword ascii
    $s18 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aGYz9(\";`)`\\x22`k`i`j`x`e`/`i`l`.`o`i`t`a`\\x22` `+` `5`b`C`a`(`h" ascii
    $s19 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aGYz9(\";`)`\\x22`k`i`j`x`e`/`i`l`.`o`i`t`a`\\x22` `+` `5`b`C`a`(`h" ascii
    $s20 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aGYz9(\"\")), 1);" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}