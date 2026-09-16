rule sig_20161214_98e44968a5369dde0c54a7508890aeb7 {
  meta:
    description = "datamaliciousorder - file 20161214_98e44968a5369dde0c54a7508890aeb7.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9ff4da7ca331db6520c771aff7bd44861fc104b8c21b0fd870cdee1093a1067f"

  strings:
    $s1  = "function aGJp6(aGAd6) {eval(\"/*@cc_on var aMFf2 = new Date() @*/\");aMFf2[\"setUTCSeconds\"](\"0\", \"20\");if (aMFf2.getUTCMil" ascii
    $s2  = "function aGJp6(aGAd6) {eval(\"/*@cc_on var aMFf2 = new Date() @*/\");aMFf2[\"setUTCSeconds\"](\"0\", \"20\");if (aMFf2.getUTCMil" ascii
    $s3  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aGJp6(\"/`*`@` `}`;`}`;`e`u`n`i`t`n`o`c`{` `)`e`(` `h`c`t`a`c`}`;`k" ascii
    $s4  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aGJp6(\";`3`f`X`a` `+` `9`k`A`W`a`=`4`j`A`a` `r`a`v\")), 1);" fullword ascii
    $s5  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aGJp6(\"}`;`h`t`a`P`t`r`o`h`S`.`6`s`Q`T`a` `n`r`u`t`e`r`;`)`2`a`V`A" ascii
    $s6  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aGJp6(\"/`*`@` `}`;`)`3`s`D`a`(`6`u`V`a` `n`r`u`t`e`r`;`)`(`e`s`o`l" ascii
    $s7  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aGJp6(\"/`*`@` `}`;`6`d`A`G`a` `n`r`u`t`e`r`;`)`\\x22`\\x22`(`]`\\x" ascii
    $s8  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aGJp6(\";`)`\\x22`p`z`e`5`i`q`p`q`5`/`h`c`.`t`e`r`u`d`e`n`i`r`e`h`t" ascii
    $s9  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aGJp6(\";`)`\\x22`p`z`e`5`i`q`p`q`5`/`h`c`.`t`e`r`u`d`e`n`i`r`e`h`t" ascii
    $s10 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aGJp6(\";`)`\\x22`c`z`6`y`7`u`j`1`w`x`/`m`o`c`.`e`k`a`w`n`a`c`i`r`e" ascii
    $s11 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aGJp6(\";`)`\\x22`h`4`u`t`k`h`5`/`o`r`.`n`i`z`a`g`a`m`q`.`e`n`u`a`c" ascii
    $s12 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aGJp6(\";`1`+`1`=`8`j`Q`V`a` `r`a`v`;`)`\\x22`t`c`e`j`b`O`m`e`t`s`y" ascii
    $s13 = "s().toString(10) == \"20\") {var aPBu2 = aGAd6[\"split\"](\"`\"); return aPBu2.reverse().join(\"\");} else return \"\";};" fullword ascii
    $s14 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aGJp6(\"/`*`@` `}`;`3`r`H`a` `n`r`u`t`e`r`;`}`;`]`h`t`g`n`e`l`.`1`p" ascii
    $s15 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aGJp6(\";`)`\\x22`x`i`1`5`x`c`y`u`/`m`o`c`.`e`l`b`u`o`d`n`i`a`r`b`" ascii
    $s16 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aGJp6(\";`)`(`y`a`r`r`A` `w`e`n` `=` `5`w`N`a` `r`a`v` ` ` ` \")), " ascii
    $s17 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aGJp6(\";`)`\\x22`P`T`T`H`L`M`X`.`2`L`M`X`S`M`\\x22`(`t`c`e`j`b`O`X" ascii
    $s18 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aGJp6(\"/`*`@` `}`;`2`u`B`P`a` `n`r`u`t`e`r`;`}`;`)`5`z`K`S`a`(`]`" ascii
    $s19 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aGJp6(\";`)`\\x22`l`l`e`h`S`.`t`p`i`r`c`S`W`\\x22`(`t`c`e`j`b`O`X`e" ascii
    $s20 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aGJp6(\"/`*`@` `}`;`6`d`A`G`a` `n`r`u`t`e`r`;`)`\\x22`\\x22`(`]`\\x" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}