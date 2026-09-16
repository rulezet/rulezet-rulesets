rule sig_20161215_3a8b5a4d58d970539b66935ccd0b7aba {
  meta:
    description = "datamaliciousorder - file 20161215_3a8b5a4d58d970539b66935ccd0b7aba.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "66979dd3703ce43b068d1a8dcde467d3bd6842cc9d138621b95a6d7d15cbc914"

  strings:
    $s1  = "function aBn1(aFe7) {eval(\"/*@cc_on var aBVw1 = new Date() @*/\");aBVw1[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aBVw1[\"getU" ascii
    $s2  = "function aBn1(aFe7) {eval(\"/*@cc_on var aBVw1 = new Date() @*/\");aBVw1[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aBVw1[\"getU" ascii
    $s3  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBn1(\";`\\x22`k`\\x22` `+` `\\x22`z`.`\\x22` `+` `3`i`Y`a`=`0`t`Y`" ascii
    $s4  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBn1(\";`)`\\x22`0`l`x`y`u`q`a`q`d`/`k`d`.`l`o`b`m`y`s`i`r`e`l`l`a`" ascii
    $s5  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBn1(\"/`*`@` `}`;`)`9`z`U`a`(`5`v`D`a` `n`r`u`t`e`r`;`)`(`e`s`o`l`" ascii
    $s6  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBn1(\"\")), 1);" fullword ascii
    $s7  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBn1(\";`\\x22`i`J`o`b`R`G`U`A`N`\\x22` `=` `9`s`G`T`a` `r`a`v` `;`" ascii
    $s8  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBn1(\";`)`\\x22`h`4`u`t`k`h`5`/`o`r`.`n`i`z`a`g`a`m`q`.`e`n`u`a`c`" ascii
    $s9  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBn1(\";`1`+`1`=`1`k`Q`Q`a` `r`a`v`;`)`\\x22`t`c`e`j`b`O`m`e`t`s`y`" ascii
    $s10 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBn1(\";`)`\\x22`l`l`e`h`S`.`t`p`i`r`c`S`W`\\x22`(`t`c`e`j`b`O`X`e`" ascii
    $s11 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBn1(\"/`*`@` `}`;`}`;`e`u`n`i`t`n`o`c`{` `)`e`(` `h`c`t`a`c`}`;`k`" ascii
    $s12 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBn1(\"/`*`@` `}`;`)`9`z`U`a`(`5`v`D`a` `n`r`u`t`e`r`;`)`(`e`s`o`l`" ascii
    $s13 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBn1(\"/`*`@` `}`;`)`(`e`s`o`l`c`.`8`s`B`a`;`)`2` `,`7`i`R`A`a`(`]`" ascii
    $s14 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBn1(\";`)`'`/`%`P`M`E`T`%`'`(`]`'`s`g`n`i`r`t`S`t`n`e`m`n`o`r`i`v`" ascii
    $s15 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBn1(\"/`*`@` `}`;`4`y`A`G`a` `n`r`u`t`e`r`;`}`;`]`h`t`g`n`e`l`.`6`" ascii
    $s16 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBn1(\";`)`\\x22`e`n`p`6`2`z`0`n`f`/`m`o`c`.`e`c`n`a`r`u`s`n`i`e`c`" ascii
    $s17 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBn1(\";`0` `=` `1`m`K`P`a` `r`a`v\")), 1);" fullword ascii
    $s18 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBn1(\"}`;`h`t`a`P`t`r`o`h`S`.`3`s`W`Z`a` `n`r`u`t`e`r`;`)`0`t`Y`K`" ascii
    $s19 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBn1(\";`\\x22`/`\\x22`+`\\x22`/`\\x22`+`\\x22`:`\\x22`+`\\x22`p`" ascii
    $s20 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBn1(\";`4`l`X`a` `+` `5`s`I`a`=`3`i`Y`a` `r`a`v\")), 1);" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}