rule sig_20161214_320ecfbfe90ac26824520142eed0ba28 {
  meta:
    description = "datamaliciousorder - file 20161214_320ecfbfe90ac26824520142eed0ba28.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "645a025d6ad6b426636ca78542eec51aa5afe54726a3ac609178a7c2a7432a10"

  strings:
    $s1  = "function aTh6(aGGc0) {eval(\"/*@cc_on var aVe9 = new Date() @*/\");aVe9[\"setUTCSeconds\"](\"0\", \"20\");if (aVe9.getUTCMillise" ascii
    $s2  = "function aTh6(aGGc0) {eval(\"/*@cc_on var aVe9 = new Date() @*/\");aVe9[\"setUTCSeconds\"](\"0\", \"20\");if (aVe9.getUTCMillise" ascii
    $s3  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aTh6(\";`\\x22`w`s`m`i`D`j`Z`K`q`8`y`2`l`w`m`3`5`J`v`f`i`i`M`f`s`m`" ascii
    $s4  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aTh6(\";`\\x22`/`\\x22`+`\\x22`/`\\x22`+`\\x22`:`\\x22`+`\\x22`p`" ascii
    $s5  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aTh6(\"/`*`@` `}`;`)`9`l`R`a`(`5`w`L`O`a` `n`r`u`t`e`r`;`)`(`e`s`o`" ascii
    $s6  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aTh6(\"/`*`@` `}`;`3`n`U`Q`a` `n`r`u`t`e`r`;`}`;`]`h`t`g`n`e`l`.`2`" ascii
    $s7  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aTh6(\"/`*`@` `}`;`)`(`e`s`o`l`c`.`7`p`J`K`a`;`)`2` `,`9`u`N`a`(`]`" ascii
    $s8  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aTh6(\";`\\x22`k`\\x22` `+` `\\x22`z`.`\\x22` `+` `5`p`P`X`a`=`0`g`" ascii
    $s9  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aTh6(\";`)`\\x22`u`z`o`j`v`p`1`d`l`/`m`o`c`.`c`f`j`l`w`z`\\x22` `+`" ascii
    $s10 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aTh6(\"/`*`@` `}`;`0`c`G`G`a` `n`r`u`t`e`r`;`)`\\x22`\\x22`(`]`\\x2" ascii
    $s11 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aTh6(\";`5`g`S`a` `+` `7`u`B`T`a`=`5`p`P`X`a` `r`a`v\")), 1);" fullword ascii
    $s12 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aTh6(\";`)`\\x22`d`0`s`y`6`z`c`g`o`/`k`d`.`n`e`r`a`a`v`\\x22` `+` `" ascii
    $s13 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aTh6(\"/`*`@` `}`;`}`;`e`u`n`i`t`n`o`c`{` `)`e`(` `h`c`t`a`c`}`;`k`" ascii
    $s14 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aTh6(\";`)`\\x22`P`T`T`H`L`M`X`.`2`L`M`X`S`M`\\x22`(`t`c`e`j`b`O`X`" ascii
    $s15 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aTh6(\";`)`\\x22`a`c`4`e`q`k`/`m`o`c`.`8`1`3`x`t`\\x22` `+` `0`l`B`" ascii
    $s16 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aTh6(\"/`*`@` `}`;`3`n`U`Q`a` `n`r`u`t`e`r`;`}`;`]`h`t`g`n`e`l`.`2`" ascii
    $s17 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aTh6(\";`\\x22`/`\\x22`+`\\x22`/`\\x22`+`\\x22`:`\\x22`+`\\x22`p`" ascii
    $s18 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aTh6(\";`)`\\x22`l`l`e`h`S`.`t`p`i`r`c`S`W`\\x22`(`t`c`e`j`b`O`X`e`" ascii
    $s19 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aTh6(\";`)`'`/`%`P`M`E`T`%`'`(`]`'`s`g`n`i`r`t`S`t`n`e`m`n`o`r`i`v`" ascii
    $s20 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aTh6(\";`)`\\x22`b`4`b`f`e`a`w`m`/`u`a`.`m`o`c`.`r`e`d`i`s`n`i`l`e`" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}