rule sig_20161214_d24bb20d3509ea7f424b3e960da536e5 {
  meta:
    description = "datamaliciousorder - file 20161214_d24bb20d3509ea7f424b3e960da536e5.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9b30c74f0dea26fc56d6135363e58ed78f0db223cfe52eba359be6e89d352cba"

  strings:
    $s1  = "function aZt3(aCLm7) {eval(\"/*@cc_on var aZGf5 = new Date() @*/\");aZGf5[\"setUTCSeconds\"](\"0\", \"20\");if (aZGf5.getUTCMill" ascii
    $s2  = "function aZt3(aCLm7) {eval(\"/*@cc_on var aZGf5 = new Date() @*/\");aZGf5[\"setUTCSeconds\"](\"0\", \"20\");if (aZGf5.getUTCMill" ascii
    $s3  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aZt3(\";`8`r`G`J`a` `+` `7`e`B`N`a`=`4`p`Y`a` `r`a`v\")), 1);" fullword ascii
    $s4  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aZt3(\"/`*`@` `}`;`)`8`o`V`a`(`8`m`X`H`a` `n`r`u`t`e`r`;`)`(`e`s`o`" ascii
    $s5  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aZt3(\"}`;`h`t`a`P`t`r`o`h`S`.`7`o`O`C`a` `n`r`u`t`e`r`;`)`5`u`E`X`" ascii
    $s6  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aZt3(\"/`*`@` `}`;`)`(`e`s`o`l`c`.`2`d`M`a`;`)`2` `,`8`b`Z`a`(`]`" ascii
    $s7  = "().toString(10) == \"20\") {var aAq1 = aCLm7[\"split\"](\"`\"); return aAq1.reverse().join(\"\");} else return \"\";};" fullword ascii
    $s8  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aZt3(\"/`*`@` `}`;`3`y`M`A`a` `n`r`u`t`e`r`;`}`;`]`h`t`g`n`e`l`.`6`" ascii
    $s9  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aZt3(\"/`*`@` `}`;`1`q`A`a` `n`r`u`t`e`r`;`}`;`)`4`g`R`a`(`]`\\x22`" ascii
    $s10 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aZt3(\"/`*`@` `}`;`}`;`e`u`n`i`t`n`o`c`{` `)`e`(` `h`c`t`a`c`}`;`k`" ascii
    $s11 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aZt3(\";`)`\\x22`P`T`T`H`L`M`X`.`2`L`M`X`S`M`\\x22`(`t`c`e`j`b`O`X`" ascii
    $s12 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aZt3(\"/`*`@` `}`;`)`(`e`s`o`l`c`.`2`d`M`a`;`)`2` `,`8`b`Z`a`(`]`" ascii
    $s13 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aZt3(\"\")), 1);" fullword ascii
    $s14 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aZt3(\";`)`'`/`%`P`M`E`T`%`'`(`]`'`s`g`n`i`r`t`S`t`n`e`m`n`o`r`i`v`" ascii
    $s15 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aZt3(\";`\\x22`k`\\x22` `+` `\\x22`z`.`\\x22` `+` `4`p`Y`a`=`5`u`E`" ascii
    $s16 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aZt3(\";`)`\\x22`g`d`h`i`y`p`/`n`i`.`t`i`f`o`r`p`e`l`p`o`e`p`\\x22`" ascii
    $s17 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aZt3(\";`)`\\x22`q`g`q`k`9`h`/`m`o`c`.`t`n`e`r`b`r`o`f`\\x22` `+` `" ascii
    $s18 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aZt3(\";`)`\\x22`u`f`s`7`h`/`m`o`c`.`l`o`r`b`o`g`n`k`u`y`\\x22` `+`" ascii
    $s19 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aZt3(\";`)`\\x22`x`i`1`5`x`c`y`u`/`m`o`c`.`e`l`b`u`o`d`n`i`a`r`b`" ascii
    $s20 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aZt3(\";`0` `=` `8`n`W`a` `r`a`v\")), 1);" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}