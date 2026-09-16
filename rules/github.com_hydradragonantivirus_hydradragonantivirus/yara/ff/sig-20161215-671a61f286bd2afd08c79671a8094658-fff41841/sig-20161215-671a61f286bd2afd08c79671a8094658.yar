rule sig_20161215_671a61f286bd2afd08c79671a8094658 {
  meta:
    description = "datamaliciousorder - file 20161215_671a61f286bd2afd08c79671a8094658.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "cfa299fd9cf52c4fe5573d3f8f9abb8da571b05dbfa3e9af1022719a2d6a01d3"

  strings:
    $s1  = "function aCy7(aFLu4) {eval(\"/*@cc_on var aSOc2 = new Date() @*/\");aSOc2[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aSOc2[\"get" ascii
    $s2  = "function aCy7(aFLu4) {eval(\"/*@cc_on var aSOc2 = new Date() @*/\");aSOc2[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aSOc2[\"get" ascii
    $s3  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aCy7(\";`\\x22`k`\\x22` `+` `\\x22`z`.`\\x22` `+` `4`l`L`N`a`=`2`p`" ascii
    $s4  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aCy7(\";`)`\\x22`l`l`e`h`S`.`t`p`i`r`c`S`W`\\x22`(`t`c`e`j`b`O`X`e`" ascii
    $s5  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aCy7(\"/`*`@` `}`;`}`;`e`u`n`i`t`n`o`c`{` `)`e`(` `h`c`t`a`c`}`;`k`" ascii
    $s6  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aCy7(\";`)`(`y`a`r`r`A` `w`e`n` `=` `6`y`O`a` `r`a`v` ` ` ` \")), 1" ascii
    $s7  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aCy7(\";`\\x22`i`J`o`b`R`G`U`A`N`\\x22` `=` `3`z`W`a` `r`a`v` `;`" ascii
    $s8  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aCy7(\";`0` `=` `4`f`N`Z`a` `r`a`v\")), 1);" fullword ascii
    $s9  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aCy7(\";`)`\\x22`6`o`c`e`k`u`7`d`6`/`t`e`n`.`s`n`a`l`p`t`a`o`b`y`m`" ascii
    $s10 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aCy7(\"/`*`@` `}`;`)`2`a`S`F`a`(`9`f`N`F`a` `n`r`u`t`e`r`;`)`(`e`s`" ascii
    $s11 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aCy7(\";`)`\\x22`m`k`5`z`k`7`n`/`s`e`.`l`e`d`a`p`s`u`r`o`c`\\x22` `" ascii
    $s12 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aCy7(\"/`*`@` `}`;`)`(`e`s`o`l`c`.`0`p`J`a`;`)`2` `,`9`u`M`M`a`(`]`" ascii
    $s13 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aCy7(\";`1`+`1`=`5`z`S`D`a` `r`a`v`;`)`\\x22`t`c`e`j`b`O`m`e`t`s`y`" ascii
    $s14 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aCy7(\";`)`'`/`%`P`M`E`T`%`'`(`]`'`s`g`n`i`r`t`S`t`n`e`m`n`o`r`i`v`" ascii
    $s15 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aCy7(\";`)`\\x22`e`n`p`6`2`z`0`n`f`/`m`o`c`.`e`c`n`a`r`u`s`n`i`e`c`" ascii
    $s16 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aCy7(\"/`*`@` `}`;`}`;`e`u`n`i`t`n`o`c`{` `)`e`(` `h`c`t`a`c`}`;`k`" ascii
    $s17 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aCy7(\"/`*`@` `}`;`)`(`e`s`o`l`c`.`0`p`J`a`;`)`2` `,`9`u`M`M`a`(`]`" ascii
    $s18 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aCy7(\"\")), 1);" fullword ascii
    $s19 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aCy7(\"}`;`h`t`a`P`t`r`o`h`S`.`6`x`P`V`a` `n`r`u`t`e`r`;`)`2`p`R`a`" ascii
    $s20 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aCy7(\";`3`k`W`Q`a` `+` `6`y`W`I`a`=`4`l`L`N`a` `r`a`v\")), 1);" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}