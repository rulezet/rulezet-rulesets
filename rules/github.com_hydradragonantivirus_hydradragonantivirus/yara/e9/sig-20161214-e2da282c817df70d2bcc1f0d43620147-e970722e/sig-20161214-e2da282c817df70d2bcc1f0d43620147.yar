rule sig_20161214_e2da282c817df70d2bcc1f0d43620147 {
  meta:
    description = "datamaliciousorder - file 20161214_e2da282c817df70d2bcc1f0d43620147.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "601d03fc8637fea7487f960ccb1e3b1b25820d72a97829f2e4500e611cc92a39"

  strings:
    $s1  = "function aQb7(aIa2) {eval(\"/*@cc_on var aQj6 = new Date() @*/\");aQj6[\"setUTCSeconds\"](\"0\", \"20\");if (aQj6.getUTCMillisec" ascii
    $s2  = "function aQb7(aIa2) {eval(\"/*@cc_on var aQj6 = new Date() @*/\");aQj6[\"setUTCSeconds\"](\"0\", \"20\");if (aQj6.getUTCMillisec" ascii
    $s3  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aQb7(\";`)`\\x22`z`9`f`w`y`e`p`f`e`e`/`m`o`c`.`e`c`i`v`r`e`s`e`n`e`" ascii
    $s4  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aQb7(\";`\\x22`/`\\x22`+`\\x22`/`\\x22`+`\\x22`:`\\x22`+`\\x22`p`" ascii
    $s5  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aQb7(\";`)`\\x22`c`o`9`o`e`e`/`n`i`.`e`l`t`t`u`h`s`-`b`e`w`\\x22` `" ascii
    $s6  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aQb7(\";`3`s`W`a` `+` `4`r`G`E`a`=`6`m`J`B`a` `r`a`v\")), 1);" fullword ascii
    $s7  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aQb7(\"/`*`@` `}`;`2`a`I`a` `n`r`u`t`e`r`;`)`\\x22`\\x22`(`]`\\x22`" ascii
    $s8  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aQb7(\"/`*`@` `}`;`2`k`B`W`a` `n`r`u`t`e`r`;`}`;`]`h`t`g`n`e`l`.`5`" ascii
    $s9  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aQb7(\"/`*`@` `}`;`)`3`q`Y`U`a`(`7`u`Y`a` `n`r`u`t`e`r`;`)`(`e`s`o`" ascii
    $s10 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aQb7(\"/`*`@` `}`;`)`(`e`s`o`l`c`.`7`w`V`a`;`)`2` `,`6`w`D`a`(`]`" ascii
    $s11 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aQb7(\";`0` `=` `7`p`N`W`a` `r`a`v\")), 1);" fullword ascii
    $s12 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aQb7(\"/`*`@` `}`;`2`k`B`W`a` `n`r`u`t`e`r`;`}`;`]`h`t`g`n`e`l`.`5`" ascii
    $s13 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aQb7(\";`)`'`/`%`P`M`E`T`%`'`(`]`'`s`g`n`i`r`t`S`t`n`e`m`n`o`r`i`v`" ascii
    $s14 = "oString(10) == \"20\") {var aCXp2 = aIa2[\"split\"](\"`\"); return aCXp2.reverse().join(\"\");} else return \"\";};" fullword ascii
    $s15 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aQb7(\";`1`+`1`=`4`b`J`X`a` `r`a`v`;`)`\\x22`t`c`e`j`b`O`m`e`t`s`y`" ascii
    $s16 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aQb7(\"/`*`@` `}`;`}`;`e`u`n`i`t`n`o`c`{` `)`e`(` `h`c`t`a`c`}`;`k`" ascii
    $s17 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aQb7(\";`\\x22`w`s`m`i`D`j`Z`K`q`8`y`2`l`w`m`3`5`J`v`f`i`i`M`f`s`m`" ascii
    $s18 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aQb7(\";`1`+`1`=`4`b`J`X`a` `r`a`v`;`)`\\x22`t`c`e`j`b`O`m`e`t`s`y`" ascii
    $s19 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aQb7(\";`)`\\x22`i`s`j`p`z`x`q`5`x`/`m`o`c`.`g`n`o`r`n`a`w`z`s`\\x2" ascii
    $s20 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aQb7(\";`)`\\x22`P`T`T`H`L`M`X`.`2`L`M`X`S`M`\\x22`(`t`c`e`j`b`O`X`" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}