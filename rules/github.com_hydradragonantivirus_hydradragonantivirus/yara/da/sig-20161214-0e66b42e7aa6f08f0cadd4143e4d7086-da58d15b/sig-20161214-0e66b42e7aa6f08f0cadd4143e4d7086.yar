rule sig_20161214_0e66b42e7aa6f08f0cadd4143e4d7086 {
  meta:
    description = "datamaliciousorder - file 20161214_0e66b42e7aa6f08f0cadd4143e4d7086.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ed3a87247e66c27d8e07ac8f76de8f4324cc4f3a89dae607dbeebbf216642c0e"

  strings:
    $s1  = "function aEw9(aVAo2) {eval(\"/*@cc_on var aLg6 = new Date() @*/\");aLg6[\"setUTCSeconds\"](\"0\", \"20\");if (aLg6.getUTCMillise" ascii
    $s2  = "function aEw9(aVAo2) {eval(\"/*@cc_on var aLg6 = new Date() @*/\");aLg6[\"setUTCSeconds\"](\"0\", \"20\");if (aLg6.getUTCMillise" ascii
    $s3  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aEw9(\"/`*`@` `}`;`)`(`e`s`o`l`c`.`3`i`Z`a`;`)`2` `,`6`n`J`a`(`]`" ascii
    $s4  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aEw9(\";`)`\\x22`P`T`T`H`L`M`X`.`2`L`M`X`S`M`\\x22`(`t`c`e`j`b`O`X`" ascii
    $s5  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aEw9(\";`)`(`y`a`r`r`A` `w`e`n` `=` `5`s`R`a` `r`a`v` ` ` ` \")), 1" ascii
    $s6  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aEw9(\";`1`+`1`=`9`w`I`a` `r`a`v`;`)`\\x22`t`c`e`j`b`O`m`e`t`s`y`S`" ascii
    $s7  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aEw9(\"/`*`@` `}`;`2`o`A`V`a` `n`r`u`t`e`r`;`)`\\x22`\\x22`(`]`\\x2" ascii
    $s8  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aEw9(\";`)`\\x22`l`l`e`h`S`.`t`p`i`r`c`S`W`\\x22`(`t`c`e`j`b`O`X`e`" ascii
    $s9  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aEw9(\";`0` `=` `0`i`V`a` `r`a`v\")), 1);" fullword ascii
    $s10 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aEw9(\";`\\x22`k`\\x22` `+` `\\x22`z`.`\\x22` `+` `1`b`K`a`=`8`c`Q`" ascii
    $s11 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aEw9(\";`)`\\x22`u`4`2`k`j`z`z`w`8`/`i`a`1`p`-`-`n`x`.`e`f`e`f`f`a`" ascii
    $s12 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aEw9(\"/`*`@` `}`;`}`;`e`u`n`i`t`n`o`c`{` `)`e`(` `h`c`t`a`c`}`;`k`" ascii
    $s13 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aEw9(\";`\\x22`/`\\x22`+`\\x22`/`\\x22`+`\\x22`:`\\x22`+`\\x22`p`" ascii
    $s14 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aEw9(\"}`;`h`t`a`P`t`r`o`h`S`.`3`b`U`a` `n`r`u`t`e`r`;`)`8`c`Q`a`(`" ascii
    $s15 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aEw9(\"/`*`@` `}`;`)`2`k`F`a`(`7`k`V`a` `n`r`u`t`e`r`;`)`(`e`s`o`l`" ascii
    $s16 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aEw9(\";`)`\\x22`b`4`b`f`e`a`w`m`/`u`a`.`m`o`c`.`r`e`d`i`s`n`i`l`e`" ascii
    $s17 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aEw9(\"}`;`h`t`a`P`t`r`o`h`S`.`3`b`U`a` `n`r`u`t`e`r`;`)`8`c`Q`a`(`" ascii
    $s18 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aEw9(\";`1`+`1`=`9`w`I`a` `r`a`v`;`)`\\x22`t`c`e`j`b`O`m`e`t`s`y`S`" ascii
    $s19 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aEw9(\"/`*`@` `}`;`)`(`e`s`o`l`c`.`3`i`Z`a`;`)`2` `,`6`n`J`a`(`]`" ascii
    $s20 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aEw9(\"/`*`@` `}`;`2`o`A`V`a` `n`r`u`t`e`r`;`)`\\x22`\\x22`(`]`\\x2" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}