rule sig_20161215_5a9b7235073965b4fd3a1f76e32d9351 {
  meta:
    description = "datamaliciousorder - file 20161215_5a9b7235073965b4fd3a1f76e32d9351.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f54274b745e8318514eae71a9fe9ac0ee2d935e54873e99f5ab6980ef9e4306c"

  strings:
    $s1  = "function aSAk3(aNn2) {eval(\"/*@cc_on var aDQu4 = new Date() @*/\");aDQu4[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aDQu4[\"get" ascii
    $s2  = "function aSAk3(aNn2) {eval(\"/*@cc_on var aDQu4 = new Date() @*/\");aDQu4[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aDQu4[\"get" ascii
    $s3  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aSAk3(\"}`;`h`t`a`P`t`r`o`h`S`.`3`z`F`a` `n`r`u`t`e`r`;`)`1`q`S`V`a" ascii
    $s4  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aSAk3(\"/`*`@` `}`;`3`f`M`W`a` `n`r`u`t`e`r`;`}`;`]`h`t`g`n`e`l`.`2" ascii
    $s5  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aSAk3(\";`1`+`1`=`3`e`A`G`a` `r`a`v`;`)`\\x22`t`c`e`j`b`O`m`e`t`s`y" ascii
    $s6  = "onds\"]()[\"toString\"](10) == \"20\") {var aPAo0 = aNn2[\"split\"](\"`\"); return aPAo0[\"reverse\"]().join(\"\");} else return" ascii
    $s7  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aSAk3(\";`)`\\x22`P`T`T`H`L`M`X`.`2`L`M`X`S`M`\\x22`(`t`c`e`j`b`O`X" ascii
    $s8  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aSAk3(\";`1`+`1`=`3`e`A`G`a` `r`a`v`;`)`\\x22`t`c`e`j`b`O`m`e`t`s`y" ascii
    $s9  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aSAk3(\";`)`'`/`%`P`M`E`T`%`'`(`]`'`s`g`n`i`r`t`S`t`n`e`m`n`o`r`i`v" ascii
    $s10 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aSAk3(\";`)`\\x22`z`l`l`b`o`6`/`m`o`c`.`l`l`e`w`o`l`l`o`h`t`a`k`\\x" ascii
    $s11 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aSAk3(\";`\\x22`k`\\x22` `+` `\\x22`z`.`\\x22` `+` `1`z`D`a`=`1`q`S" ascii
    $s12 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aSAk3(\"/`*`@` `}`;`2`n`N`a` `n`r`u`t`e`r`;`)`\\x22`\\x22`(`]`\\x22" ascii
    $s13 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aSAk3(\"/`*`@` `}`;`3`f`M`W`a` `n`r`u`t`e`r`;`}`;`]`h`t`g`n`e`l`.`2" ascii
    $s14 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aSAk3(\";`\\x22`/`\\x22`+`\\x22`/`\\x22`+`\\x22`:`\\x22`+`\\x22`p`" ascii
    $s15 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aSAk3(\";`)`\\x22`z`c`x`t`e`w`v`e`6`/`z`i`b`.`e`r`o`c`i`n`u`m`m`o`c" ascii
    $s16 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aSAk3(\"/`*`@` `}`;`2`n`N`a` `n`r`u`t`e`r`;`)`\\x22`\\x22`(`]`\\x22" ascii
    $s17 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aSAk3(\";`)`\\x22`z`c`x`t`e`w`v`e`6`/`z`i`b`.`e`r`o`c`i`n`u`m`m`o`c" ascii
    $s18 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aSAk3(\";`)`\\x22`l`l`e`h`S`.`t`p`i`r`c`S`W`\\x22`(`t`c`e`j`b`O`X`e" ascii
    $s19 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aSAk3(\";`1`s`C`a` `+` `9`q`C`R`a`=`1`z`D`a` `r`a`v\")), 1);" fullword ascii
    $s20 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aSAk3(\";`)`\\x22`k`i`j`x`e`/`i`l`.`o`i`t`a`\\x22` `+` `6`z`G`a`(`h" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}