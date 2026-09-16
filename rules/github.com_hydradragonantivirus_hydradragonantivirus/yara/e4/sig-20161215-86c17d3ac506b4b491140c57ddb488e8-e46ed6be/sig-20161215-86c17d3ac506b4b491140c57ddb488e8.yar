rule sig_20161215_86c17d3ac506b4b491140c57ddb488e8 {
  meta:
    description = "datamaliciousorder - file 20161215_86c17d3ac506b4b491140c57ddb488e8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "85a91a1e9740f7e33524a414e39d50080793f9e3a2e06d828f6e4c4b083d1b90"

  strings:
    $s1  = "function aJLj6(aUCb2) {eval(\"/*@cc_on var aGw0 = new Date() @*/\");aGw0[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aGw0[\"getUT" ascii
    $s2  = "function aJLj6(aUCb2) {eval(\"/*@cc_on var aGw0 = new Date() @*/\");aGw0[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aGw0[\"getUT" ascii
    $s3  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aJLj6(\";`)`\\x22`l`l`e`h`S`.`t`p`i`r`c`S`W`\\x22`(`t`c`e`j`b`O`X`e" ascii
    $s4  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aJLj6(\"/`*`@` `}`;`4`w`K`G`a` `n`r`u`t`e`r`;`}`;`)`2`x`U`a`(`]`\\x" ascii
    $s5  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aJLj6(\";`)`\\x22`P`T`T`H`L`M`X`.`2`L`M`X`S`M`\\x22`(`t`c`e`j`b`O`X" ascii
    $s6  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aJLj6(\"/`*`@` `}`;`}`;`e`u`n`i`t`n`o`c`{` `)`e`(` `h`c`t`a`c`}`;`k" ascii
    $s7  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aJLj6(\"/`*`@` `}`;`6`q`H`C`a` `n`r`u`t`e`r`;`}`;`]`h`t`g`n`e`l`.`4" ascii
    $s8  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aJLj6(\"/`*`@` `}`;`2`b`C`U`a` `n`r`u`t`e`r`;`)`\\x22`\\x22`(`]`\\x" ascii
    $s9  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aJLj6(\"/`*`@` `}`;`)`(`e`s`o`l`c`.`0`h`Q`a`;`)`2` `,`2`h`H`D`a`(`]" ascii
    $s10 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aJLj6(\";`\\x22`k`\\x22` `+` `\\x22`z`.`\\x22` `+` `5`o`C`a`=`5`m`P" ascii
    $s11 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aJLj6(\";`)`\\x22`u`z`o`j`v`p`1`d`l`/`m`o`c`.`c`f`j`l`w`z`\\x22` `+" ascii
    $s12 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aJLj6(\";`)`\\x22`l`l`e`h`S`.`t`p`i`r`c`S`W`\\x22`(`t`c`e`j`b`O`X`e" ascii
    $s13 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aJLj6(\";`1`+`1`=`6`y`J`a` `r`a`v`;`)`\\x22`t`c`e`j`b`O`m`e`t`s`y`S" ascii
    $s14 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aJLj6(\"/`*`@` `}`;`)`1`c`L`S`a`(`2`l`L`a` `n`r`u`t`e`r`;`)`(`e`s`o" ascii
    $s15 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aJLj6(\";`)`\\x22`e`m`n`n`6`o`t`/`g`r`o`.`r`e`d`o`u`c`\\x22` `+` `8" ascii
    $s16 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aJLj6(\";`0` `=` `6`r`G`W`a` `r`a`v\")), 1);" fullword ascii
    $s17 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aJLj6(\";`\\x22`i`J`o`b`R`G`U`A`N`\\x22` `=` `8`x`M`a` `r`a`v` `;`" ascii
    $s18 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aJLj6(\";`)`\\x22`u`z`o`j`v`p`1`d`l`/`m`o`c`.`c`f`j`l`w`z`\\x22` `+" ascii
    $s19 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aJLj6(\";`)`(`y`a`r`r`A` `w`e`n` `=` `6`l`Q`a` `r`a`v` ` ` ` \")), " ascii
    $s20 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aJLj6(\";`4`h`K`a` `+` `1`t`Y`a`=`5`o`C`a` `r`a`v\")), 1);" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}