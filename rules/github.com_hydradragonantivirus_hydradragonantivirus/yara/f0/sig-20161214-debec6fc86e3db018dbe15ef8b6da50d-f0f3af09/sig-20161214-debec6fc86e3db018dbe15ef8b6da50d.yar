rule sig_20161214_debec6fc86e3db018dbe15ef8b6da50d {
  meta:
    description = "datamaliciousorder - file 20161214_debec6fc86e3db018dbe15ef8b6da50d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "feaf074d7d3255c8255d3945cfdd000c7ee9b3933eeceeaca5dcfdab69084c82"

  strings:
    $s1  = "function aUFs5(aAHr4) {eval(\"/*@cc_on var aKd2 = new Date() @*/\");aKd2[\"setUTCSeconds\"](\"0\", \"20\");if (aKd2.getUTCMillis" ascii
    $s2  = "function aUFs5(aAHr4) {eval(\"/*@cc_on var aKd2 = new Date() @*/\");aKd2[\"setUTCSeconds\"](\"0\", \"20\");if (aKd2.getUTCMillis" ascii
    $s3  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aUFs5(\";`\\x22`/`\\x22`+`\\x22`/`\\x22`+`\\x22`:`\\x22`+`\\x22`p`" ascii
    $s4  = ".toString(10) == \"20\") {var aTRp5 = aAHr4[\"split\"](\"`\"); return aTRp5.reverse().join(\"\");} else return \"\";};" fullword ascii
    $s5  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aUFs5(\"/`*`@` `}`;`5`p`R`T`a` `n`r`u`t`e`r`;`}`;`)`5`i`J`a`(`]`\\x" ascii
    $s6  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aUFs5(\";`\\x22`k`\\x22` `+` `\\x22`z`.`\\x22` `+` `4`l`S`X`a`=`5`c" ascii
    $s7  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aUFs5(\"/`*`@` `}`;`6`r`O`a` `n`r`u`t`e`r`;`}`;`]`h`t`g`n`e`l`.`3`o" ascii
    $s8  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aUFs5(\";`)`\\x22`a`c`4`e`q`k`/`m`o`c`.`8`1`3`x`t`\\x22` `+` `4`i`T" ascii
    $s9  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aUFs5(\";`)`\\x22`p`c`6`k`7`/`u`r`.`t`s`u`d`-`i`t`n`a`\\x22` `+` `4" ascii
    $s10 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aUFs5(\"/`*`@` `}`;`}`;`e`u`n`i`t`n`o`c`{` `)`e`(` `h`c`t`a`c`}`;`k" ascii
    $s11 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aUFs5(\";`)`\\x22`u`4`2`k`j`z`z`w`8`/`i`a`1`p`-`-`n`x`.`e`f`e`f`f`a" ascii
    $s12 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aUFs5(\";`)`\\x22`a`g`9`d`2`h`6`b`i`k`/`n`c`.`3`2`1`d`y`f`\\x22` `+" ascii
    $s13 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aUFs5(\"}`;`h`t`a`P`t`r`o`h`S`.`4`o`U`O`a` `n`r`u`t`e`r`;`)`5`c`E`a" ascii
    $s14 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aUFs5(\"/`*`@` `}`;`)`(`e`s`o`l`c`.`7`x`T`W`a`;`)`2` `,`0`s`S`C`a`(" ascii
    $s15 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aUFs5(\"/`*`@` `}`;`5`p`R`T`a` `n`r`u`t`e`r`;`}`;`)`5`i`J`a`(`]`\\x" ascii
    $s16 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aUFs5(\";`)`\\x22`P`T`T`H`L`M`X`.`2`L`M`X`S`M`\\x22`(`t`c`e`j`b`O`X" ascii
    $s17 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aUFs5(\";`)`\\x22`u`z`o`j`v`p`1`d`l`/`m`o`c`.`c`f`j`l`w`z`\\x22` `+" ascii
    $s18 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aUFs5(\";`)`'`/`%`P`M`E`T`%`'`(`]`'`s`g`n`i`r`t`S`t`n`e`m`n`o`r`i`v" ascii
    $s19 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aUFs5(\";`)`\\x22`p`c`6`k`7`/`u`r`.`t`s`u`d`-`i`t`n`a`\\x22` `+` `4" ascii
    $s20 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aUFs5(\";`)`\\x22`a`c`4`e`q`k`/`m`o`c`.`8`1`3`x`t`\\x22` `+` `4`i`T" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}