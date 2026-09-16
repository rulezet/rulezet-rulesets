rule sig_20161215_489897167223416df8668b07e7fa7752 {
  meta:
    description = "datamaliciousorder - file 20161215_489897167223416df8668b07e7fa7752.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "214992c25efc930f4e7aa42e73b424697e8a51234be5de92798a2638e5e1cbb7"

  strings:
    $s1  = "function aCg1(aFHg6) {eval(\"/*@cc_on var aNb1 = new Date() @*/\");aNb1[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aNb1[\"getUTC" ascii
    $s2  = "function aCg1(aFHg6) {eval(\"/*@cc_on var aNb1 = new Date() @*/\");aNb1[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aNb1[\"getUTC" ascii
    $s3  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aCg1(\"/`*`@` `}`;`7`l`X`L`a` `n`r`u`t`e`r`;`}`;`]`h`t`g`n`e`l`.`9`" ascii
    $s4  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aCg1(\";`)`\\x22`7`g`u`b`g`m`y`c`q`/`m`o`c`.`t`f`o`s`y`l`e`s`i`w`" ascii
    $s5  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aCg1(\";`)`'`/`%`P`M`E`T`%`'`(`]`'`s`g`n`i`r`t`S`t`n`e`m`n`o`r`i`v`" ascii
    $s6  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aCg1(\";`0` `=` `4`e`S`X`a` `r`a`v\")), 1);" fullword ascii
    $s7  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aCg1(\"\")), 1);" fullword ascii
    $s8  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aCg1(\"/`*`@` `}`;`}`;`e`u`n`i`t`n`o`c`{` `)`e`(` `h`c`t`a`c`}`;`k`" ascii
    $s9  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aCg1(\";`)`\\x22`7`k`8`p`c`q`/`a`c`.`r`e`v`u`o`c`n`a`v`r`i`a`p`e`r`" ascii
    $s10 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aCg1(\"/`*`@` `}`;`)`(`e`s`o`l`c`.`8`c`L`A`a`;`)`2` `,`1`c`J`a`(`]`" ascii
    $s11 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aCg1(\";`1`+`1`=`9`u`P`a` `r`a`v`;`)`\\x22`t`c`e`j`b`O`m`e`t`s`y`S`" ascii
    $s12 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aCg1(\";`\\x22`k`\\x22` `+` `\\x22`z`.`\\x22` `+` `0`i`E`Y`a`=`6`x`" ascii
    $s13 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aCg1(\"}`;`h`t`a`P`t`r`o`h`S`.`8`p`W`M`a` `n`r`u`t`e`r`;`)`6`x`D`U`" ascii
    $s14 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aCg1(\";`\\x22`i`J`o`b`R`G`U`A`N`\\x22` `=` `7`v`L`a` `r`a`v` `;`" ascii
    $s15 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aCg1(\"}`;`h`t`a`P`t`r`o`h`S`.`8`p`W`M`a` `n`r`u`t`e`r`;`)`6`x`D`U`" ascii
    $s16 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aCg1(\";`)`\\x22`l`l`e`h`S`.`t`p`i`r`c`S`W`\\x22`(`t`c`e`j`b`O`X`e`" ascii
    $s17 = "s\"]()[\"toString\"](10) == \"20\") {var aEWz6 = aFHg6[\"split\"](\"`\"); return aEWz6[\"reverse\"]().join(\"\");} else return " ascii
    $s18 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aCg1(\";`)`\\x22`l`y`k`0`o`n`r`t`c`i`/`m`o`c`.`s`r`e`i`r`r`e`t`x`o`" ascii
    $s19 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aCg1(\";`)`\\x22`P`T`T`H`L`M`X`.`2`L`M`X`S`M`\\x22`(`t`c`e`j`b`O`X`" ascii
    $s20 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aCg1(\";`)`\\x22`t`w`e`x`d`z`f`/`s`e`.`p`r`a`h`s`s`a`r`o`d`a`i`p`o`" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}