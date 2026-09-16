rule sig_20161214_3a1b9a66ede2d6a92b7ff2a7faf6e78e {
  meta:
    description = "datamaliciousorder - file 20161214_3a1b9a66ede2d6a92b7ff2a7faf6e78e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c01f913312e0da214ae05c5e28ba9f9804e17c6863ead544db8f562421689b12"

  strings:
    $s1  = "function aTEw3(aCq5) {eval(\"/*@cc_on var aHn6 = new Date() @*/\");aHn6[\"setUTCSeconds\"](\"0\", \"20\");if (aHn6.getUTCMillise" ascii
    $s2  = "function aTEw3(aCq5) {eval(\"/*@cc_on var aHn6 = new Date() @*/\");aHn6[\"setUTCSeconds\"](\"0\", \"20\");if (aHn6.getUTCMillise" ascii
    $s3  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aTEw3(\";`\\x22`k`\\x22` `+` `\\x22`z`.`\\x22` `+` `2`x`B`G`a`=`6`m" ascii
    $s4  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aTEw3(\";`1`+`1`=`7`c`Y`a` `r`a`v`;`)`\\x22`t`c`e`j`b`O`m`e`t`s`y`S" ascii
    $s5  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aTEw3(\";`\\x22`/`\\x22`+`\\x22`/`\\x22`+`\\x22`:`\\x22`+`\\x22`p`" ascii
    $s6  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aTEw3(\";`)`\\x22`p`h`c`y`l`a`h`l`d`/`d`i`.`o`g`.`b`a`k`a`y`a`r`s`a" ascii
    $s7  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aTEw3(\";`)`\\x22`u`u`1`d`m`q`/`u`a`.`t`e`n`.`s`l`e`e`h`w`n`o`k`l`a" ascii
    $s8  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aTEw3(\";`0` `=` `1`i`S`a` `r`a`v\")), 1);" fullword ascii
    $s9  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aTEw3(\"/`*`@` `}`;`}`;`e`u`n`i`t`n`o`c`{` `)`e`(` `h`c`t`a`c`}`;`k" ascii
    $s10 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aTEw3(\"/`*`@` `}`;`}`;`e`u`n`i`t`n`o`c`{` `)`e`(` `h`c`t`a`c`}`;`k" ascii
    $s11 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aTEw3(\";`)`\\x22`7`w`1`o`y`d`/`m`o`c`.`n`g`i`s`e`d`m`e`r`a`u`q`s`." ascii
    $s12 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aTEw3(\"/`*`@` `}`;`5`q`C`a` `n`r`u`t`e`r`;`)`\\x22`\\x22`(`]`\\x22" ascii
    $s13 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aTEw3(\"/`*`@` `}`;`)`8`s`D`J`a`(`7`f`K`J`a` `n`r`u`t`e`r`;`)`(`e`s" ascii
    $s14 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aTEw3(\"/`*`@` `}`;`1`e`O`T`a` `n`r`u`t`e`r`;`}`;`]`h`t`g`n`e`l`.`7" ascii
    $s15 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aTEw3(\";`)`\\x22`u`u`1`d`m`q`/`u`a`.`t`e`n`.`s`l`e`e`h`w`n`o`k`l`a" ascii
    $s16 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aTEw3(\";`)`\\x22`u`6`b`s`z`y`p`d`/`m`o`c`.`b`g`s`o`f`e`d`e`h`\\x22" ascii
    $s17 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aTEw3(\";`)`\\x22`7`o`k`y`5`l`s`/`l`p`.`i`n`h`c`u`k`o`d`o`k`t`s`y`z" ascii
    $s18 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aTEw3(\"/`*`@` `}`;`)`8`s`D`J`a`(`7`f`K`J`a` `n`r`u`t`e`r`;`)`(`e`s" ascii
    $s19 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aTEw3(\"/`*`@` `}`;`2`n`O`a` `n`r`u`t`e`r`;`}`;`)`9`o`O`T`a`(`]`\\x" ascii
    $s20 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aTEw3(\";`)`(`y`a`r`r`A` `w`e`n` `=` `8`w`V`J`a` `r`a`v` ` ` ` \"))" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}