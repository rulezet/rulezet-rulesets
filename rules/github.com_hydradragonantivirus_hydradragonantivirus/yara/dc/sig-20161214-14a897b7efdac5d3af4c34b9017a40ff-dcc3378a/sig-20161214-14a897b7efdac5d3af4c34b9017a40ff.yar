rule sig_20161214_14a897b7efdac5d3af4c34b9017a40ff {
  meta:
    description = "datamaliciousorder - file 20161214_14a897b7efdac5d3af4c34b9017a40ff.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "43d076073536fd8e1c09f79c604bfd10ea4c0b5cd58d65a079dbd766b2156e76"

  strings:
    $s1  = "function aCl1(aWZe1) {eval(\"/*@cc_on var aCSu9 = new Date() @*/\");aCSu9[\"setUTCSeconds\"](\"0\", \"20\");if (aCSu9.getUTCMill" ascii
    $s2  = "function aCl1(aWZe1) {eval(\"/*@cc_on var aCSu9 = new Date() @*/\");aCSu9[\"setUTCSeconds\"](\"0\", \"20\");if (aCSu9.getUTCMill" ascii
    $s3  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aCl1(\"\")), 1);" fullword ascii
    $s4  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aCl1(\";`)`\\x22`m`a`1`q`z`z`4`/`l`n`.`e`d`o`h`t`e`m`k`n`a`l`s`\\x2" ascii
    $s5  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aCl1(\"/`*`@` `}`;`)`7`u`T`Y`a`(`7`t`U`Q`a` `n`r`u`t`e`r`;`)`(`e`s`" ascii
    $s6  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aCl1(\";`)`\\x22`g`d`h`i`y`p`/`n`i`.`t`i`f`o`r`p`e`l`p`o`e`p`\\x22`" ascii
    $s7  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aCl1(\";`\\x22`/`\\x22`+`\\x22`/`\\x22`+`\\x22`:`\\x22`+`\\x22`p`" ascii
    $s8  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aCl1(\";`)`\\x22`0`8`v`i`r`u`g`j`m`/`m`o`c`.`s`y`b`u`s`\\x22` `+` `" ascii
    $s9  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aCl1(\";`0` `=` `4`u`D`a` `r`a`v\")), 1);" fullword ascii
    $s10 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aCl1(\";`\\x22`w`s`m`i`D`j`Z`K`q`8`y`2`l`w`m`3`5`J`v`f`i`i`M`f`s`m`" ascii
    $s11 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aCl1(\";`1`v`F`S`a` `+` `0`r`X`a`=`8`z`K`Q`a` `r`a`v\")), 1);" fullword ascii
    $s12 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aCl1(\";`)`'`/`%`P`M`E`T`%`'`(`]`'`s`g`n`i`r`t`S`t`n`e`m`n`o`r`i`v`" ascii
    $s13 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aCl1(\"/`*`@` `}`;`)`(`e`s`o`l`c`.`9`z`E`a`;`)`2` `,`8`f`S`a`(`]`" ascii
    $s14 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aCl1(\";`1`+`1`=`0`f`V`a` `r`a`v`;`)`\\x22`t`c`e`j`b`O`m`e`t`s`y`S`" ascii
    $s15 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aCl1(\";`)`\\x22`l`l`e`h`S`.`t`p`i`r`c`S`W`\\x22`(`t`c`e`j`b`O`X`e`" ascii
    $s16 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aCl1(\"/`*`@` `}`;`)`(`e`s`o`l`c`.`9`z`E`a`;`)`2` `,`8`f`S`a`(`]`" ascii
    $s17 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aCl1(\"/`*`@` `}`;`7`c`I`a` `n`r`u`t`e`r`;`}`;`]`h`t`g`n`e`l`.`6`e`" ascii
    $s18 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aCl1(\";`)`(`y`a`r`r`A` `w`e`n` `=` `6`g`F`D`a` `r`a`v` ` ` ` \"))," ascii
    $s19 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aCl1(\"/`*`@` `}`;`5`b`A`C`a` `n`r`u`t`e`r`;`}`;`)`1`s`D`a`(`]`\\x2" ascii
    $s20 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aCl1(\"/`*`@` `}`;`}`;`e`u`n`i`t`n`o`c`{` `)`e`(` `h`c`t`a`c`}`;`k`" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}