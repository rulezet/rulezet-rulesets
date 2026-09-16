rule sig_20161215_44d5a7b03ad769caf8acfb03a7fb08ac {
  meta:
    description = "datamaliciousorder - file 20161215_44d5a7b03ad769caf8acfb03a7fb08ac.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3759ef58b0695fb1f4979c92817acbf1bef54944b2640cafcf5caae32838b550"

  strings:
    $s1  = "function aOZq8(aYUq9) {eval(\"/*@cc_on var aXGq3 = new Date() @*/\");aXGq3[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aXGq3[\"ge" ascii
    $s2  = "function aOZq8(aYUq9) {eval(\"/*@cc_on var aXGq3 = new Date() @*/\");aXGq3[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aXGq3[\"ge" ascii
    $s3  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aOZq8(\"}`;`h`t`a`P`t`r`o`h`S`.`3`e`U`Q`a` `n`r`u`t`e`r`;`)`7`q`P`a" ascii
    $s4  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aOZq8(\";`0`s`E`a` `+` `5`s`G`a`=`6`e`W`a` `r`a`v\")), 1);" fullword ascii
    $s5  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aOZq8(\";`)`\\x22`P`T`T`H`L`M`X`.`2`L`M`X`S`M`\\x22`(`t`c`e`j`b`O`X" ascii
    $s6  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aOZq8(\"/`*`@` `}`;`)`1`d`Q`I`a`(`9`h`D`B`a` `n`r`u`t`e`r`;`)`(`e`s" ascii
    $s7  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aOZq8(\"/`*`@` `}`;`9`q`U`Y`a` `n`r`u`t`e`r`;`)`\\x22`\\x22`(`]`\\x" ascii
    $s8  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aOZq8(\";`)`\\x22`1`p`a`y`d`/`s`e`.`r`a`c`i`f`a`\\x22` `+` `0`h`D`O" ascii
    $s9  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aOZq8(\";`\\x22`i`J`o`b`R`G`U`A`N`\\x22` `=` `1`a`A`a` `r`a`v` `;`" ascii
    $s10 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aOZq8(\";`)`(`y`a`r`r`A` `w`e`n` `=` `9`z`C`G`a` `r`a`v` ` ` ` \"))" ascii
    $s11 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aOZq8(\";`)`\\x22`l`l`e`h`S`.`t`p`i`r`c`S`W`\\x22`(`t`c`e`j`b`O`X`e" ascii
    $s12 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aOZq8(\";`)`\\x22`h`4`u`t`k`h`5`/`o`r`.`n`i`z`a`g`a`m`q`.`e`n`u`a`c" ascii
    $s13 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aOZq8(\";`)`\\x22`e`n`p`6`2`z`0`n`f`/`m`o`c`.`e`c`n`a`r`u`s`n`i`e`c" ascii
    $s14 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aOZq8(\"/`*`@` `}`;`}`;`e`u`n`i`t`n`o`c`{` `)`e`(` `h`c`t`a`c`}`;`k" ascii
    $s15 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aOZq8(\";`)`'`/`%`P`M`E`T`%`'`(`]`'`s`g`n`i`r`t`S`t`n`e`m`n`o`r`i`v" ascii
    $s16 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aOZq8(\"/`*`@` `}`;`9`g`T`a` `n`r`u`t`e`r`;`}`;`]`h`t`g`n`e`l`.`6`k" ascii
    $s17 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aOZq8(\";`)`\\x22`0`l`x`y`u`q`a`q`d`/`k`d`.`l`o`b`m`y`s`i`r`e`l`l`a" ascii
    $s18 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aOZq8(\";`)`'`/`%`P`M`E`T`%`'`(`]`'`s`g`n`i`r`t`S`t`n`e`m`n`o`r`i`v" ascii
    $s19 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aOZq8(\";`\\x22`i`J`o`b`R`G`U`A`N`\\x22` `=` `1`a`A`a` `r`a`v` `;`" ascii
    $s20 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aOZq8(\"/`*`@` `}`;`9`q`U`Y`a` `n`r`u`t`e`r`;`)`\\x22`\\x22`(`]`\\x" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}