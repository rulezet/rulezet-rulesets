rule sig_20161215_57a90019ca549a22ca9d134bd07212b7 {
  meta:
    description = "datamaliciousorder - file 20161215_57a90019ca549a22ca9d134bd07212b7.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f9921231d6091e75a1c403ab7b9e21147da7d4f2198b67c6ad330968da18cdb2"

  strings:
    $s1  = "function aGf3(aWUy2) {eval(\"/*@cc_on var aXUf9 = new Date() @*/\");aXUf9[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aXUf9[\"get" ascii
    $s2  = "function aGf3(aWUy2) {eval(\"/*@cc_on var aXUf9 = new Date() @*/\");aXUf9[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aXUf9[\"get" ascii
    $s3  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aGf3(\";`)`\\x22`b`u`r`v`2`m`7`/`v`t`.`e`t`a`g`d`o`o`g`\\x22` `+` `" ascii
    $s4  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aGf3(\";`)`\\x22`l`l`e`h`S`.`t`p`i`r`c`S`W`\\x22`(`t`c`e`j`b`O`X`e`" ascii
    $s5  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aGf3(\"/`*`@` `}`;`}`;`e`u`n`i`t`n`o`c`{` `)`e`(` `h`c`t`a`c`}`;`k`" ascii
    $s6  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aGf3(\";`)`\\x22`u`u`t`h`l`k`w`t`6`/`m`o`c`.`z`a`p`o`l`b`a`p`\\x22`" ascii
    $s7  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aGf3(\"/`*`@` `}`;`)`(`e`s`o`l`c`.`2`e`I`I`a`;`)`2` `,`7`c`N`O`a`(`" ascii
    $s8  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aGf3(\";`\\x22`/`\\x22`+`\\x22`/`\\x22`+`\\x22`:`\\x22`+`\\x22`p`" ascii
    $s9  = "onds\"]()[\"toString\"](10) == \"20\") {var aIn0 = aWUy2[\"split\"](\"`\"); return aIn0[\"reverse\"]().join(\"\");} else return " ascii
    $s10 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aGf3(\"/`*`@` `}`;`2`y`U`W`a` `n`r`u`t`e`r`;`)`\\x22`\\x22`(`]`\\x2" ascii
    $s11 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aGf3(\";`)`'`/`%`P`M`E`T`%`'`(`]`'`s`g`n`i`r`t`S`t`n`e`m`n`o`r`i`v`" ascii
    $s12 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aGf3(\";`)`\\x22`P`T`T`H`L`M`X`.`2`L`M`X`S`M`\\x22`(`t`c`e`j`b`O`X`" ascii
    $s13 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aGf3(\"}`;`h`t`a`P`t`r`o`h`S`.`3`a`L`E`a` `n`r`u`t`e`r`;`)`3`f`T`a`" ascii
    $s14 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aGf3(\"/`*`@` `}`;`)`(`e`s`o`l`c`.`2`e`I`I`a`;`)`2` `,`7`c`N`O`a`(`" ascii
    $s15 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aGf3(\";`)`\\x22`u`f`s`7`h`/`m`o`c`.`l`o`r`b`o`g`n`k`u`y`\\x22` `+`" ascii
    $s16 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aGf3(\";`\\x22`i`J`o`b`R`G`U`A`N`\\x22` `=` `7`h`S`C`a` `r`a`v` `;`" ascii
    $s17 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aGf3(\"/`*`@` `}`;`0`n`I`a` `n`r`u`t`e`r`;`}`;`)`6`j`V`T`a`(`]`\\x2" ascii
    $s18 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aGf3(\";`\\x22`k`\\x22` `+` `\\x22`z`.`\\x22` `+` `9`j`Q`a`=`3`f`T`" ascii
    $s19 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aGf3(\"\")), 1);" fullword ascii
    $s20 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aGf3(\"}`;`h`t`a`P`t`r`o`h`S`.`3`a`L`E`a` `n`r`u`t`e`r`;`)`3`f`T`a`" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}