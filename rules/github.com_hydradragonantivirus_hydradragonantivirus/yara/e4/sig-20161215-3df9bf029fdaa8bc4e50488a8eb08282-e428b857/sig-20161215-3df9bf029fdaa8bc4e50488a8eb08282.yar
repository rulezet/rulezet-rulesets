rule sig_20161215_3df9bf029fdaa8bc4e50488a8eb08282 {
  meta:
    description = "datamaliciousorder - file 20161215_3df9bf029fdaa8bc4e50488a8eb08282.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "637d7854202aa47d21d0eeaccd995727f55ad945d0d71a9a9f87cdd841eedcd7"

  strings:
    $s1  = "function aYr8(aDu7) {eval(\"/*@cc_on var aQk4 = new Date() @*/\");aQk4[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aQk4[\"getUTCM" ascii
    $s2  = "function aYr8(aDu7) {eval(\"/*@cc_on var aQk4 = new Date() @*/\");aQk4[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aQk4[\"getUTCM" ascii
    $s3  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aYr8(\"/`*`@` `}`;`8`e`F`W`a` `n`r`u`t`e`r`;`}`;`]`h`t`g`n`e`l`.`0`" ascii
    $s4  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aYr8(\";`\\x22`i`J`o`b`R`G`U`A`N`\\x22` `=` `5`g`M`U`a` `r`a`v` `;`" ascii
    $s5  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aYr8(\";`)`\\x22`u`z`o`j`v`p`1`d`l`/`m`o`c`.`c`f`j`l`w`z`\\x22` `+`" ascii
    $s6  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aYr8(\";`\\x22`k`\\x22` `+` `\\x22`z`.`\\x22` `+` `9`c`B`a`=`1`c`D`" ascii
    $s7  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aYr8(\";`0` `=` `9`s`F`Z`a` `r`a`v\")), 1);" fullword ascii
    $s8  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aYr8(\"/`*`@` `}`;`)`7`m`X`a`(`0`q`R`a` `n`r`u`t`e`r`;`)`(`e`s`o`l`" ascii
    $s9  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aYr8(\";`\\x22`/`\\x22`+`\\x22`/`\\x22`+`\\x22`:`\\x22`+`\\x22`p`" ascii
    $s10 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aYr8(\";`)`\\x22`e`m`n`n`6`o`t`/`g`r`o`.`r`e`d`o`u`c`\\x22` `+` `9`" ascii
    $s11 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aYr8(\";`\\x22`i`J`o`b`R`G`U`A`N`\\x22` `=` `5`g`M`U`a` `r`a`v` `;`" ascii
    $s12 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aYr8(\";`)`\\x22`l`l`e`h`S`.`t`p`i`r`c`S`W`\\x22`(`t`c`e`j`b`O`X`e`" ascii
    $s13 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aYr8(\"/`*`@` `}`;`8`e`F`W`a` `n`r`u`t`e`r`;`}`;`]`h`t`g`n`e`l`.`0`" ascii
    $s14 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aYr8(\";`)`\\x22`3`2`i`t`s`/`m`o`c`.`s`b`e`w`0`5`.`e`c`i`v`d`a`l`a`" ascii
    $s15 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aYr8(\";`)`(`y`a`r`r`A` `w`e`n` `=` `6`x`N`a` `r`a`v` ` ` ` \")), 1" ascii
    $s16 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aYr8(\";`1`+`1`=`1`c`G`P`a` `r`a`v`;`)`\\x22`t`c`e`j`b`O`m`e`t`s`y`" ascii
    $s17 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aYr8(\"\")), 1);" fullword ascii
    $s18 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aYr8(\";`\\x22`k`\\x22` `+` `\\x22`z`.`\\x22` `+` `9`c`B`a`=`1`c`D`" ascii
    $s19 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aYr8(\";`4`k`M`G`a` `+` `7`w`A`W`a`=`9`c`B`a` `r`a`v\")), 1);" fullword ascii
    $s20 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aYr8(\"/`*`@` `}`;`}`;`e`u`n`i`t`n`o`c`{` `)`e`(` `h`c`t`a`c`}`;`k`" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}