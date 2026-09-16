rule sig_20161215_9f17807c6422a7967e121813ceefc4b9 {
  meta:
    description = "datamaliciousorder - file 20161215_9f17807c6422a7967e121813ceefc4b9.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e38d0a2d4b0f8335e61ac5dfb5cdbc53931555b3f685182398b09913ddb42b35"

  strings:
    $s1  = "function aYi8(aBm3) {eval(\"/*@cc_on var aBe4 = new Date() @*/\");aBe4[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aBe4[\"getUTCM" ascii
    $s2  = "function aYi8(aBm3) {eval(\"/*@cc_on var aBe4 = new Date() @*/\");aBe4[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aBe4[\"getUTCM" ascii
    $s3  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aYi8(\";`1`+`1`=`2`s`R`a` `r`a`v`;`)`\\x22`t`c`e`j`b`O`m`e`t`s`y`S`" ascii
    $s4  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aYi8(\";`)`'`/`%`P`M`E`T`%`'`(`]`'`s`g`n`i`r`t`S`t`n`e`m`n`o`r`i`v`" ascii
    $s5  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aYi8(\";`)`'`/`%`P`M`E`T`%`'`(`]`'`s`g`n`i`r`t`S`t`n`e`m`n`o`r`i`v`" ascii
    $s6  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aYi8(\"/`*`@` `}`;`)`(`e`s`o`l`c`.`9`g`Z`M`a`;`)`2` `,`0`n`K`a`(`]`" ascii
    $s7  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aYi8(\";`)`\\x22`c`o`9`o`e`e`/`n`i`.`e`l`t`t`u`h`s`-`b`e`w`\\x22` `" ascii
    $s8  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aYi8(\";`\\x22`/`\\x22`+`\\x22`/`\\x22`+`\\x22`:`\\x22`+`\\x22`p`" ascii
    $s9  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aYi8(\";`1`+`1`=`2`s`R`a` `r`a`v`;`)`\\x22`t`c`e`j`b`O`m`e`t`s`y`S`" ascii
    $s10 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aYi8(\"/`*`@` `}`;`3`m`B`a` `n`r`u`t`e`r`;`)`\\x22`\\x22`(`]`\\x22`" ascii
    $s11 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aYi8(\";`\\x22`/`\\x22`+`\\x22`/`\\x22`+`\\x22`:`\\x22`+`\\x22`p`" ascii
    $s12 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aYi8(\";`)`\\x22`l`n`t`i`u`8`6`/`k`u`.`o`c`.`t`a`a`w`\\x22` `+` `9`" ascii
    $s13 = "\"]()[\"toString\"](10) == \"20\") {var aIFz5 = aBm3[\"split\"](\"`\"); return aIFz5[\"reverse\"]().join(\"\");} else return \"" ascii
    $s14 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aYi8(\";`)`(`y`a`r`r`A` `w`e`n` `=` `6`p`U`a` `r`a`v` ` ` ` \")), 1" ascii
    $s15 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aYi8(\";`)`\\x22`z`9`f`w`y`e`p`f`e`e`/`m`o`c`.`e`c`i`v`r`e`s`e`n`e`" ascii
    $s16 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aYi8(\"/`*`@` `}`;`5`z`F`I`a` `n`r`u`t`e`r`;`}`;`)`7`q`C`J`a`(`]`" ascii
    $s17 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aYi8(\"/`*`@` `}`;`}`;`e`u`n`i`t`n`o`c`{` `)`e`(` `h`c`t`a`c`}`;`k`" ascii
    $s18 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aYi8(\"/`*`@` `}`;`9`c`W`a` `n`r`u`t`e`r`;`}`;`]`h`t`g`n`e`l`.`0`c`" ascii
    $s19 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aYi8(\";`0` `=` `0`z`J`R`a` `r`a`v\")), 1);" fullword ascii
    $s20 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aYi8(\";`2`k`R`a` `+` `4`e`Y`I`a`=`1`v`N`a` `r`a`v\")), 1);" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}