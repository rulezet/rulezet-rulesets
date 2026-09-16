rule sig_20161215_c1c3f26d5a8e7e39adf9b8d0c587ceb8 {
  meta:
    description = "datamaliciousorder - file 20161215_c1c3f26d5a8e7e39adf9b8d0c587ceb8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fdcceeb6e69e5afd9237bbe67a57b62ce2095b910d785b096f2a98a52da1f4c0"

  strings:
    $s1  = "function aQCc5(aSHp3) {eval(\"/*@cc_on var aPn8 = new Date() @*/\");aPn8[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aPn8[\"getUT" ascii
    $s2  = "function aQCc5(aSHp3) {eval(\"/*@cc_on var aPn8 = new Date() @*/\");aPn8[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aPn8[\"getUT" ascii
    $s3  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aQCc5(\";`)`\\x22`d`t`r`2`l`s`4`/`r`f`.`1`1`1`1`m`f`\\x22` `+` `0`r" ascii
    $s4  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aQCc5(\";`)`\\x22`7`w`1`o`y`d`/`m`o`c`.`n`g`i`s`e`d`m`e`r`a`u`q`s`." ascii
    $s5  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aQCc5(\";`)`\\x22`l`l`e`h`S`.`t`p`i`r`c`S`W`\\x22`(`t`c`e`j`b`O`X`e" ascii
    $s6  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aQCc5(\"/`*`@` `}`;`2`z`W`a` `n`r`u`t`e`r`;`}`;`)`9`p`W`C`a`(`]`\\x" ascii
    $s7  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aQCc5(\";`)`\\x22`7`w`1`o`y`d`/`m`o`c`.`n`g`i`s`e`d`m`e`r`a`u`q`s`." ascii
    $s8  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aQCc5(\";`1`+`1`=`8`f`L`M`a` `r`a`v`;`)`\\x22`t`c`e`j`b`O`m`e`t`s`y" ascii
    $s9  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aQCc5(\"\")), 1);" fullword ascii
    $s10 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aQCc5(\";`)`'`/`%`P`M`E`T`%`'`(`]`'`s`g`n`i`r`t`S`t`n`e`m`n`o`r`i`v" ascii
    $s11 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aQCc5(\"/`*`@` `}`;`)`0`z`W`a`(`1`k`H`E`a` `n`r`u`t`e`r`;`)`(`e`s`o" ascii
    $s12 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aQCc5(\";`\\x22`/`\\x22`+`\\x22`/`\\x22`+`\\x22`:`\\x22`+`\\x22`p`" ascii
    $s13 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aQCc5(\";`\\x22`k`\\x22` `+` `\\x22`z`.`\\x22` `+` `1`c`L`a`=`4`e`Q" ascii
    $s14 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aQCc5(\"/`*`@` `}`;`)`0`z`W`a`(`1`k`H`E`a` `n`r`u`t`e`r`;`)`(`e`s`o" ascii
    $s15 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aQCc5(\";`\\x22`i`J`o`b`R`G`U`A`N`\\x22` `=` `9`s`S`L`a` `r`a`v` `;" ascii
    $s16 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aQCc5(\";`)`\\x22`l`l`e`h`S`.`t`p`i`r`c`S`W`\\x22`(`t`c`e`j`b`O`X`e" ascii
    $s17 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aQCc5(\"/`*`@` `}`;`)`(`e`s`o`l`c`.`8`g`K`K`a`;`)`2` `,`4`r`Z`B`a`(" ascii
    $s18 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aQCc5(\"/`*`@` `}`;`3`p`H`S`a` `n`r`u`t`e`r`;`)`\\x22`\\x22`(`]`\\x" ascii
    $s19 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aQCc5(\"/`*`@` `}`;`2`z`W`a` `n`r`u`t`e`r`;`}`;`)`9`p`W`C`a`(`]`\\x" ascii
    $s20 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aQCc5(\";`)`\\x22`P`T`T`H`L`M`X`.`2`L`M`X`S`M`\\x22`(`t`c`e`j`b`O`X" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}