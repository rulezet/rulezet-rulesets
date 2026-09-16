rule sig_20161215_044fa3209ebf1f9ce820ed9302f36017 {
  meta:
    description = "datamaliciousorder - file 20161215_044fa3209ebf1f9ce820ed9302f36017.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "93528bab50b38204321e6f3d38cd5b9d12e890a0e0f4dab932e22282bb132fda"

  strings:
    $s1  = "function aLAz7(aZSv9) {eval(\"/*@cc_on var aEm0 = new Date() @*/\");aEm0[\"setUTCSeconds\"](\"0\", \"20\");if (aEm0.getUTCMillis" ascii
    $s2  = "function aLAz7(aZSv9) {eval(\"/*@cc_on var aEm0 = new Date() @*/\");aEm0[\"setUTCSeconds\"](\"0\", \"20\");if (aEm0.getUTCMillis" ascii
    $s3  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aLAz7(\";`6`z`U`Y`a` `+` `6`g`K`a`=`4`s`O`L`a` `r`a`v\")), 1);" fullword ascii
    $s4  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aLAz7(\";`)`\\x22`l`l`e`h`S`.`t`p`i`r`c`S`W`\\x22`(`t`c`e`j`b`O`X`e" ascii
    $s5  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aLAz7(\"/`*`@` `}`;`2`q`S`a` `n`r`u`t`e`r`;`}`;`)`7`f`G`S`a`(`]`\\x" ascii
    $s6  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aLAz7(\";`)`\\x22`q`j`s`v`b`/`m`o`c`.`e`r`a`p`s`i`h`s`.`o`m`e`d`\\x" ascii
    $s7  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aLAz7(\"}`;`h`t`a`P`t`r`o`h`S`.`5`q`G`A`a` `n`r`u`t`e`r`;`)`8`v`E`a" ascii
    $s8  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aLAz7(\"/`*`@` `}`;`9`v`S`Z`a` `n`r`u`t`e`r`;`)`\\x22`\\x22`(`]`\\x" ascii
    $s9  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aLAz7(\";`)`\\x22`l`u`r`v`c`d`b`f`q`/`m`o`c`.`w`u`y`i`h`z`\\x22` `+" ascii
    $s10 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aLAz7(\";`)`\\x22`P`T`T`H`L`M`X`.`2`L`M`X`S`M`\\x22`(`t`c`e`j`b`O`X" ascii
    $s11 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aLAz7(\";`)`\\x22`o`w`b`3`k`5`n`i`n`/`m`o`c`.`3`2`1`t`s`e`t`x`0`1`t" ascii
    $s12 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aLAz7(\"}`;`h`t`a`P`t`r`o`h`S`.`5`q`G`A`a` `n`r`u`t`e`r`;`)`8`v`E`a" ascii
    $s13 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aLAz7(\"\")), 1);" fullword ascii
    $s14 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aLAz7(\";`)`\\x22`d`w`n`h`3`c`m`/`m`o`c`.`i`a`i`d`u`w`\\x22` `+` `3" ascii
    $s15 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aLAz7(\";`\\x22`/`\\x22`+`\\x22`/`\\x22`+`\\x22`:`\\x22`+`\\x22`p`" ascii
    $s16 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aLAz7(\";`1`+`1`=`0`y`Y`B`a` `r`a`v`;`)`\\x22`t`c`e`j`b`O`m`e`t`s`y" ascii
    $s17 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aLAz7(\";`\\x22`k`\\x22` `+` `\\x22`z`.`\\x22` `+` `4`s`O`L`a`=`8`v" ascii
    $s18 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aLAz7(\"/`*`@` `}`;`}`;`e`u`n`i`t`n`o`c`{` `)`e`(` `h`c`t`a`c`}`;`k" ascii
    $s19 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aLAz7(\";`\\x22`/`\\x22`+`\\x22`/`\\x22`+`\\x22`:`\\x22`+`\\x22`p`" ascii
    $s20 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aLAz7(\";`)`\\x22`l`l`e`h`S`.`t`p`i`r`c`S`W`\\x22`(`t`c`e`j`b`O`X`e" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}