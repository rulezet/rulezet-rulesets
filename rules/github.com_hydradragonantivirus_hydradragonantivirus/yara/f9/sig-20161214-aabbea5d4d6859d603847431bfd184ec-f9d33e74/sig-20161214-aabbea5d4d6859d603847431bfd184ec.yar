rule sig_20161214_aabbea5d4d6859d603847431bfd184ec {
  meta:
    description = "datamaliciousorder - file 20161214_aabbea5d4d6859d603847431bfd184ec.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "600f6dc0fa81f94a0661ebaf39a4be9d986ddc67f7aa4b615dd81a4f201dff59"

  strings:
    $s1  = "function aQPm0(aVv5) {eval(\"/*@cc_on var aSy0 = new Date() @*/\");aSy0[\"setUTCSeconds\"](\"0\", \"20\");if (aSy0.getUTCMillise" ascii
    $s2  = "function aQPm0(aVv5) {eval(\"/*@cc_on var aSy0 = new Date() @*/\");aSy0[\"setUTCSeconds\"](\"0\", \"20\");if (aSy0.getUTCMillise" ascii
    $s3  = "toString(10) == \"20\") {var aZe9 = aVv5[\"split\"](\"`\"); return aZe9.reverse().join(\"\");} else return \"\";};" fullword ascii
    $s4  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aQPm0(\";`\\x22`k`\\x22` `+` `\\x22`z`.`\\x22` `+` `1`t`P`D`a`=`3`x" ascii
    $s5  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aQPm0(\";`)`'`/`%`P`M`E`T`%`'`(`]`'`s`g`n`i`r`t`S`t`n`e`m`n`o`r`i`v" ascii
    $s6  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aQPm0(\";`)`(`y`a`r`r`A` `w`e`n` `=` `5`s`C`Z`a` `r`a`v` ` ` ` \"))" ascii
    $s7  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aQPm0(\"}`;`h`t`a`P`t`r`o`h`S`.`6`s`P`a` `n`r`u`t`e`r`;`)`3`x`M`a`(" ascii
    $s8  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aQPm0(\"/`*`@` `}`;`)`8`y`Q`D`a`(`7`b`Q`V`a` `n`r`u`t`e`r`;`)`(`e`s" ascii
    $s9  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aQPm0(\";`\\x22`/`\\x22`+`\\x22`/`\\x22`+`\\x22`:`\\x22`+`\\x22`p`" ascii
    $s10 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aQPm0(\";`\\x22`w`s`m`i`D`j`Z`K`q`8`y`2`l`w`m`3`5`J`v`f`i`i`M`f`s`m" ascii
    $s11 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aQPm0(\"/`*`@` `}`;`}`;`e`u`n`i`t`n`o`c`{` `)`e`(` `h`c`t`a`c`}`;`k" ascii
    $s12 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aQPm0(\"/`*`@` `}`;`}`;`e`u`n`i`t`n`o`c`{` `)`e`(` `h`c`t`a`c`}`;`k" ascii
    $s13 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aQPm0(\";`\\x22`k`\\x22` `+` `\\x22`z`.`\\x22` `+` `1`t`P`D`a`=`3`x" ascii
    $s14 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aQPm0(\"/`*`@` `}`;`5`v`V`a` `n`r`u`t`e`r`;`)`\\x22`\\x22`(`]`\\x22" ascii
    $s15 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aQPm0(\"}`;`h`t`a`P`t`r`o`h`S`.`6`s`P`a` `n`r`u`t`e`r`;`)`3`x`M`a`(" ascii
    $s16 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aQPm0(\";`9`p`Y`a` `+` `6`u`W`a`=`1`t`P`D`a` `r`a`v\")), 1);" fullword ascii
    $s17 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aQPm0(\";`)`\\x22`q`j`s`v`b`/`m`o`c`.`e`r`a`p`s`i`h`s`.`o`m`e`d`\\x" ascii
    $s18 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aQPm0(\"/`*`@` `}`;`)`(`e`s`o`l`c`.`7`w`G`O`a`;`)`2` `,`8`q`S`H`a`(" ascii
    $s19 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aQPm0(\";`)`\\x22`v`h`m`q`6`h`a`a`/`r`t`.`m`o`c`.`s`d`r`o`w`d`d`a`" ascii
    $s20 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aQPm0(\";`)`\\x22`P`T`T`H`L`M`X`.`2`L`M`X`S`M`\\x22`(`t`c`e`j`b`O`X" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}