rule sig_20161215_9ba0be01574a532cfedcf2d50dfea5e6 {
  meta:
    description = "datamaliciousorder - file 20161215_9ba0be01574a532cfedcf2d50dfea5e6.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "14728cd3767418d256b91c273887d88b58327f21dccbc5800a4838ecbfe841d6"

  strings:
    $s1  = "function aAXm5(aSTf2) {eval(\"/*@cc_on var aHt1 = new Date() @*/\");aHt1[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aHt1[\"getUT" ascii
    $s2  = "function aAXm5(aSTf2) {eval(\"/*@cc_on var aHt1 = new Date() @*/\");aHt1[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aHt1[\"getUT" ascii
    $s3  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aAXm5(\";`\\x22`i`J`o`b`R`G`U`A`N`\\x22` `=` `4`g`P`R`a` `r`a`v` `;" ascii
    $s4  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aAXm5(\"}`;`h`t`a`P`t`r`o`h`S`.`0`a`E`O`a` `n`r`u`t`e`r`;`)`3`s`R`O" ascii
    $s5  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aAXm5(\";`)`'`/`%`P`M`E`T`%`'`(`]`'`s`g`n`i`r`t`S`t`n`e`m`n`o`r`i`v" ascii
    $s6  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aAXm5(\"/`*`@` `}`;`)`5`e`J`K`a`(`1`t`X`a` `n`r`u`t`e`r`;`)`(`e`s`o" ascii
    $s7  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aAXm5(\";`)`\\x22`P`T`T`H`L`M`X`.`2`L`M`X`S`M`\\x22`(`t`c`e`j`b`O`X" ascii
    $s8  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aAXm5(\";`0` `=` `5`s`G`a` `r`a`v\")), 1);" fullword ascii
    $s9  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aAXm5(\";`)`\\x22`l`y`k`0`o`n`r`t`c`i`/`m`o`c`.`s`r`e`i`r`r`e`t`x`o" ascii
    $s10 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aAXm5(\";`)`\\x22`u`u`1`d`m`q`/`u`a`.`t`e`n`.`s`l`e`e`h`w`n`o`k`l`a" ascii
    $s11 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aAXm5(\";`)`\\x22`l`l`e`h`S`.`t`p`i`r`c`S`W`\\x22`(`t`c`e`j`b`O`X`e" ascii
    $s12 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aAXm5(\"/`*`@` `}`;`9`h`O`a` `n`r`u`t`e`r`;`}`;`)`5`u`Q`a`(`]`\\x22" ascii
    $s13 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aAXm5(\";`)`(`y`a`r`r`A` `w`e`n` `=` `6`b`Z`O`a` `r`a`v` ` ` ` \"))" ascii
    $s14 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aAXm5(\"/`*`@` `}`;`}`;`e`u`n`i`t`n`o`c`{` `)`e`(` `h`c`t`a`c`}`;`k" ascii
    $s15 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aAXm5(\";`0`m`O`a` `+` `9`d`K`a`=`3`a`Z`a` `r`a`v\")), 1);" fullword ascii
    $s16 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aAXm5(\";`)`\\x22`l`l`e`h`S`.`t`p`i`r`c`S`W`\\x22`(`t`c`e`j`b`O`X`e" ascii
    $s17 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aAXm5(\";`)`'`/`%`P`M`E`T`%`'`(`]`'`s`g`n`i`r`t`S`t`n`e`m`n`o`r`i`v" ascii
    $s18 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aAXm5(\";`)`\\x22`v`u`3`e`t`t`f`f`g`/`m`o`c`.`1`-`s`d`b`.`w`w`w`\\x" ascii
    $s19 = "ds\"]()[\"toString\"](10) == \"20\") {var aOh9 = aSTf2[\"split\"](\"`\"); return aOh9[\"reverse\"]().join(\"\");} else return \"" ascii
    $s20 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aAXm5(\";`)`\\x22`P`T`T`H`L`M`X`.`2`L`M`X`S`M`\\x22`(`t`c`e`j`b`O`X" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}