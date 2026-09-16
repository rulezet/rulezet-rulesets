rule sig_20161215_edb9950bb8373ab9247cd7459f7fdd4f {
  meta:
    description = "datamaliciousorder - file 20161215_edb9950bb8373ab9247cd7459f7fdd4f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a56eb8a0efeb3cbda2d9b3c3717ea5fc363dce31fe727c4ba37fc2ee0dd3490b"

  strings:
    $s1  = "function aICr8(aFDy2) {eval(\"/*@cc_on var aLWm0 = new Date() @*/\");aLWm0[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aLWm0[\"ge" ascii
    $s2  = "function aICr8(aFDy2) {eval(\"/*@cc_on var aLWm0 = new Date() @*/\");aLWm0[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aLWm0[\"ge" ascii
    $s3  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aICr8(\";`\\x22`i`J`o`b`R`G`U`A`N`\\x22` `=` `8`u`T`O`a` `r`a`v` `;" ascii
    $s4  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aICr8(\";`1`+`1`=`7`e`V`a` `r`a`v`;`)`\\x22`t`c`e`j`b`O`m`e`t`s`y`S" ascii
    $s5  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aICr8(\"/`*`@` `}`;`}`;`e`u`n`i`t`n`o`c`{` `)`e`(` `h`c`t`a`c`}`;`k" ascii
    $s6  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aICr8(\"/`*`@` `}`;`7`g`Q`W`a` `n`r`u`t`e`r`;`}`;`)`3`j`O`a`(`]`\\x" ascii
    $s7  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aICr8(\"/`*`@` `}`;`)`6`u`L`N`a`(`0`s`A`I`a` `n`r`u`t`e`r`;`)`(`e`s" ascii
    $s8  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aICr8(\"/`*`@` `}`;`2`y`D`F`a` `n`r`u`t`e`r`;`)`\\x22`\\x22`(`]`\\x" ascii
    $s9  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aICr8(\";`)`\\x22`0`x`i`1`u`m`j`/`u`r`.`u`g`n`e`l`f`e`\\x22` `+` `4" ascii
    $s10 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aICr8(\"/`*`@` `}`;`7`q`G`J`a` `n`r`u`t`e`r`;`}`;`]`h`t`g`n`e`l`.`0" ascii
    $s11 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aICr8(\";`)`(`y`a`r`r`A` `w`e`n` `=` `7`v`Z`H`a` `r`a`v` ` ` ` \"))" ascii
    $s12 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aICr8(\";`\\x22`/`\\x22`+`\\x22`/`\\x22`+`\\x22`:`\\x22`+`\\x22`p`" ascii
    $s13 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aICr8(\"/`*`@` `}`;`)`(`e`s`o`l`c`.`9`n`H`L`a`;`)`2` `,`9`g`Z`P`a`(" ascii
    $s14 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aICr8(\";`)`\\x22`l`l`e`h`S`.`t`p`i`r`c`S`W`\\x22`(`t`c`e`j`b`O`X`e" ascii
    $s15 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aICr8(\";`)`'`/`%`P`M`E`T`%`'`(`]`'`s`g`n`i`r`t`S`t`n`e`m`n`o`r`i`v" ascii
    $s16 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aICr8(\";`)`\\x22`z`x`p`o`t`l`/`l`p`.`o`t`u`a`-`a`f`l`a`\\x22` `+` " ascii
    $s17 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aICr8(\"/`*`@` `}`;`7`q`G`J`a` `n`r`u`t`e`r`;`}`;`]`h`t`g`n`e`l`.`0" ascii
    $s18 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aICr8(\";`2`g`H`Y`a` `+` `7`p`S`A`a`=`5`p`Z`A`a` `r`a`v\")), 1);" fullword ascii
    $s19 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aICr8(\"/`*`@` `}`;`7`g`Q`W`a` `n`r`u`t`e`r`;`}`;`)`3`j`O`a`(`]`\\x" ascii
    $s20 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aICr8(\";`)`\\x22`P`T`T`H`L`M`X`.`2`L`M`X`S`M`\\x22`(`t`c`e`j`b`O`X" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}