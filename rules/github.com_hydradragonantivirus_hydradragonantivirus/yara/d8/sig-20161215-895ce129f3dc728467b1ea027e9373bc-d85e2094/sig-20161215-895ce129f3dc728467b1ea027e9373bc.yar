rule sig_20161215_895ce129f3dc728467b1ea027e9373bc {
  meta:
    description = "datamaliciousorder - file 20161215_895ce129f3dc728467b1ea027e9373bc.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2fd1ed9ac771118241a52d62346528f709953bea9815a76f1a4a5c14bfaf1d95"

  strings:
    $s1  = "function aSf7(aJPs1) {eval(\"/*@cc_on var aZAk6 = new Date() @*/\");aZAk6[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aZAk6[\"get" ascii
    $s2  = "function aSf7(aJPs1) {eval(\"/*@cc_on var aZAk6 = new Date() @*/\");aZAk6[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aZAk6[\"get" ascii
    $s3  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aSf7(\";`)`\\x22`P`T`T`H`L`M`X`.`2`L`M`X`S`M`\\x22`(`t`c`e`j`b`O`X`" ascii
    $s4  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aSf7(\"/`*`@` `}`;`1`s`P`J`a` `n`r`u`t`e`r`;`)`\\x22`\\x22`(`]`\\x2" ascii
    $s5  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aSf7(\";`)`\\x22`u`u`t`h`l`k`w`t`6`/`m`o`c`.`z`a`p`o`l`b`a`p`\\x22`" ascii
    $s6  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aSf7(\";`\\x22`k`\\x22` `+` `\\x22`z`.`\\x22` `+` `9`i`Z`O`a`=`3`v`" ascii
    $s7  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aSf7(\"/`*`@` `}`;`)`9`a`M`a`(`1`i`P`U`a` `n`r`u`t`e`r`;`)`(`e`s`o`" ascii
    $s8  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aSf7(\";`)`\\x22`k`i`j`x`e`/`i`l`.`o`i`t`a`\\x22` `+` `5`l`H`O`a`(`" ascii
    $s9  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aSf7(\";`)`\\x22`z`c`x`t`e`w`v`e`6`/`z`i`b`.`e`r`o`c`i`n`u`m`m`o`c`" ascii
    $s10 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aSf7(\";`)`\\x22`k`i`j`x`e`/`i`l`.`o`i`t`a`\\x22` `+` `5`l`H`O`a`(`" ascii
    $s11 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aSf7(\";`0` `=` `7`b`Q`M`a` `r`a`v\")), 1);" fullword ascii
    $s12 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aSf7(\"}`;`h`t`a`P`t`r`o`h`S`.`8`a`V`a` `n`r`u`t`e`r`;`)`3`v`Q`a`(`" ascii
    $s13 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aSf7(\";`1`+`1`=`4`p`V`V`a` `r`a`v`;`)`\\x22`t`c`e`j`b`O`m`e`t`s`y`" ascii
    $s14 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aSf7(\"/`*`@` `}`;`4`m`X`a` `n`r`u`t`e`r`;`}`;`)`5`v`R`a`(`]`\\x22`" ascii
    $s15 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aSf7(\";`\\x22`i`J`o`b`R`G`U`A`N`\\x22` `=` `2`f`U`V`a` `r`a`v` `;`" ascii
    $s16 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aSf7(\";`)`\\x22`c`1`s`b`b`g`/`l`p`.`m`a`e`r`d`s`a`\\x22` `+` `5`l`" ascii
    $s17 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aSf7(\";`)`\\x22`l`l`e`h`S`.`t`p`i`r`c`S`W`\\x22`(`t`c`e`j`b`O`X`e`" ascii
    $s18 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aSf7(\";`)`\\x22`z`l`l`b`o`6`/`m`o`c`.`l`l`e`w`o`l`l`o`h`t`a`k`\\x2" ascii
    $s19 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aSf7(\"/`*`@` `}`;`)`(`e`s`o`l`c`.`9`z`C`a`;`)`2` `,`1`q`P`E`a`(`]`" ascii
    $s20 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aSf7(\"/`*`@` `}`;`}`;`e`u`n`i`t`n`o`c`{` `)`e`(` `h`c`t`a`c`}`;`k`" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}