rule sig_20161214_ddf589ec70ee3d9fc9ed5da68a09159d {
  meta:
    description = "datamaliciousorder - file 20161214_ddf589ec70ee3d9fc9ed5da68a09159d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "eeafeec669820740ac29e4d5880d3944668e6653c7391d9af38016bb873dfe8d"

  strings:
    $s1  = "function aWp9(aIQl9) {eval(\"/*@cc_on var aLRo7 = new Date() @*/\");aLRo7[\"setUTCSeconds\"](\"0\", \"20\");if (aLRo7.getUTCMill" ascii
    $s2  = "function aWp9(aIQl9) {eval(\"/*@cc_on var aLRo7 = new Date() @*/\");aLRo7[\"setUTCSeconds\"](\"0\", \"20\");if (aLRo7.getUTCMill" ascii
    $s3  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aWp9(\";`)`(`y`a`r`r`A` `w`e`n` `=` `1`o`B`a` `r`a`v` ` ` ` \")), 1" ascii
    $s4  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aWp9(\";`1`+`1`=`4`w`H`a` `r`a`v`;`)`\\x22`t`c`e`j`b`O`m`e`t`s`y`S`" ascii
    $s5  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aWp9(\"/`*`@` `}`;`)`6`b`N`Y`a`(`4`f`X`a` `n`r`u`t`e`r`;`)`(`e`s`o`" ascii
    $s6  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aWp9(\";`)`'`/`%`P`M`E`T`%`'`(`]`'`s`g`n`i`r`t`S`t`n`e`m`n`o`r`i`v`" ascii
    $s7  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aWp9(\"/`*`@` `}`;`9`l`Q`I`a` `n`r`u`t`e`r`;`)`\\x22`\\x22`(`]`\\x2" ascii
    $s8  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aWp9(\";`)`\\x22`l`l`e`h`S`.`t`p`i`r`c`S`W`\\x22`(`t`c`e`j`b`O`X`e`" ascii
    $s9  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aWp9(\"/`*`@` `}`;`7`u`U`Y`a` `n`r`u`t`e`r`;`}`;`)`0`q`B`S`a`(`]`" ascii
    $s10 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aWp9(\"/`*`@` `}`;`}`;`e`u`n`i`t`n`o`c`{` `)`e`(` `h`c`t`a`c`}`;`k`" ascii
    $s11 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aWp9(\";`)`\\x22`o`w`b`3`k`5`n`i`n`/`m`o`c`.`3`2`1`t`s`e`t`x`0`1`t`" ascii
    $s12 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aWp9(\";`)`\\x22`7`g`u`b`g`m`y`c`q`/`m`o`c`.`t`f`o`s`y`l`e`s`i`w`" ascii
    $s13 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aWp9(\";`)`\\x22`u`u`1`d`m`q`/`u`a`.`t`e`n`.`s`l`e`e`h`w`n`o`k`l`a`" ascii
    $s14 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aWp9(\"/`*`@` `}`;`)`(`e`s`o`l`c`.`3`j`V`a`;`)`2` `,`0`d`T`a`(`]`" ascii
    $s15 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aWp9(\"/`*`@` `}`;`0`s`S`a` `n`r`u`t`e`r`;`}`;`]`h`t`g`n`e`l`.`8`z`" ascii
    $s16 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aWp9(\";`)`'`/`%`P`M`E`T`%`'`(`]`'`s`g`n`i`r`t`S`t`n`e`m`n`o`r`i`v`" ascii
    $s17 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aWp9(\"/`*`@` `}`;`9`l`Q`I`a` `n`r`u`t`e`r`;`)`\\x22`\\x22`(`]`\\x2" ascii
    $s18 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aWp9(\";`)`\\x22`P`T`T`H`L`M`X`.`2`L`M`X`S`M`\\x22`(`t`c`e`j`b`O`X`" ascii
    $s19 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aWp9(\";`0`r`G`K`a` `+` `7`o`C`a`=`3`r`Y`a` `r`a`v\")), 1);" fullword ascii
    $s20 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aWp9(\"}`;`h`t`a`P`t`r`o`h`S`.`7`g`Z`H`a` `n`r`u`t`e`r`;`)`8`j`U`V`" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}