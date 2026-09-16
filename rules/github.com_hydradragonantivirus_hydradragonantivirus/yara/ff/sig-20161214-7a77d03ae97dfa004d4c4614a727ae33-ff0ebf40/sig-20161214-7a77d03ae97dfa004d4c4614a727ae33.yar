rule sig_20161214_7a77d03ae97dfa004d4c4614a727ae33 {
  meta:
    description = "datamaliciousorder - file 20161214_7a77d03ae97dfa004d4c4614a727ae33.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4b61bacb21158ed7019db6a088faa4abf39789aa89d749005d135b1008dc386c"

  strings:
    $s1  = "function aVTw9(aVm3) {eval(\"/*@cc_on var aHc4 = new Date() @*/\");aHc4[\"setUTCSeconds\"](\"0\", \"20\");if (aHc4.getUTCMillise" ascii
    $s2  = "function aVTw9(aVm3) {eval(\"/*@cc_on var aHc4 = new Date() @*/\");aHc4[\"setUTCSeconds\"](\"0\", \"20\");if (aHc4.getUTCMillise" ascii
    $s3  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aVTw9(\";`)`\\x22`z`9`f`w`y`e`p`f`e`e`/`m`o`c`.`e`c`i`v`r`e`s`e`n`e" ascii
    $s4  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aVTw9(\";`)`\\x22`v`v`6`c`z`a`d`f`u`/`u`r`.`s`t`r`e`s`t`u`o`h`u`b`" ascii
    $s5  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aVTw9(\";`\\x22`k`\\x22` `+` `\\x22`z`.`\\x22` `+` `3`g`R`D`a`=`2`u" ascii
    $s6  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aVTw9(\";`)`\\x22`c`o`9`o`e`e`/`n`i`.`e`l`t`t`u`h`s`-`b`e`w`\\x22` " ascii
    $s7  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aVTw9(\"/`*`@` `}`;`)`(`e`s`o`l`c`.`8`y`E`K`a`;`)`2` `,`6`i`R`a`(`]" ascii
    $s8  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aVTw9(\";`)`(`y`a`r`r`A` `w`e`n` `=` `1`p`T`a` `r`a`v` ` ` ` \")), " ascii
    $s9  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aVTw9(\"/`*`@` `}`;`3`y`J`a` `n`r`u`t`e`r`;`}`;`)`4`g`Q`C`a`(`]`\\x" ascii
    $s10 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aVTw9(\";`0` `=` `2`a`Q`X`a` `r`a`v\")), 1);" fullword ascii
    $s11 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aVTw9(\"}`;`h`t`a`P`t`r`o`h`S`.`9`l`I`a` `n`r`u`t`e`r`;`)`2`u`B`a`(" ascii
    $s12 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aVTw9(\";`)`\\x22`z`9`f`w`y`e`p`f`e`e`/`m`o`c`.`e`c`i`v`r`e`s`e`n`e" ascii
    $s13 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aVTw9(\";`)`\\x22`v`v`6`c`z`a`d`f`u`/`u`r`.`s`t`r`e`s`t`u`o`h`u`b`" ascii
    $s14 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aVTw9(\"/`*`@` `}`;`)`(`e`s`o`l`c`.`8`y`E`K`a`;`)`2` `,`6`i`R`a`(`]" ascii
    $s15 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aVTw9(\"/`*`@` `}`;`1`g`B`a` `n`r`u`t`e`r`;`}`;`]`h`t`g`n`e`l`.`9`i" ascii
    $s16 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aVTw9(\";`1`+`1`=`0`x`O`G`a` `r`a`v`;`)`\\x22`t`c`e`j`b`O`m`e`t`s`y" ascii
    $s17 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aVTw9(\";`)`\\x22`7`w`1`o`y`d`/`m`o`c`.`n`g`i`s`e`d`m`e`r`a`u`q`s`." ascii
    $s18 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aVTw9(\";`)`\\x22`l`l`e`h`S`.`t`p`i`r`c`S`W`\\x22`(`t`c`e`j`b`O`X`e" ascii
    $s19 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aVTw9(\";`)`'`/`%`P`M`E`T`%`'`(`]`'`s`g`n`i`r`t`S`t`n`e`m`n`o`r`i`v" ascii
    $s20 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aVTw9(\"/`*`@` `}`;`}`;`e`u`n`i`t`n`o`c`{` `)`e`(` `h`c`t`a`c`}`;`k" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}