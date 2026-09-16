rule sig_20161214_6459722b7e0d4893eba33667d8698e11 {
  meta:
    description = "datamaliciousorder - file 20161214_6459722b7e0d4893eba33667d8698e11.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d961bbc5b87ed29fca5832e3cf991a27269bf6f68df43ae7603cd77a81e0fbd6"

  strings:
    $s1  = "function aFd7(aIv6) {eval(\"/*@cc_on var aZl9 = new Date() @*/\");aZl9[\"setUTCSeconds\"](\"0\", \"20\");if (aZl9.getUTCMillisec" ascii
    $s2  = "function aFd7(aIv6) {eval(\"/*@cc_on var aZl9 = new Date() @*/\");aZl9[\"setUTCSeconds\"](\"0\", \"20\");if (aZl9.getUTCMillisec" ascii
    $s3  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aFd7(\"/`*`@` `}`;`)`(`e`s`o`l`c`.`6`i`T`D`a`;`)`2` `,`2`l`U`O`a`(`" ascii
    $s4  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aFd7(\"\")), 1);" fullword ascii
    $s5  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aFd7(\";`)`\\x22`q`j`s`v`b`/`m`o`c`.`e`r`a`p`s`i`h`s`.`o`m`e`d`\\x2" ascii
    $s6  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aFd7(\";`)`\\x22`p`h`c`y`l`a`h`l`d`/`d`i`.`o`g`.`b`a`k`a`y`a`r`s`a`" ascii
    $s7  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aFd7(\";`\\x22`/`\\x22`+`\\x22`/`\\x22`+`\\x22`:`\\x22`+`\\x22`p`" ascii
    $s8  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aFd7(\";`)`\\x22`q`j`s`v`b`/`m`o`c`.`e`r`a`p`s`i`h`s`.`o`m`e`d`\\x2" ascii
    $s9  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aFd7(\"/`*`@` `}`;`)`4`j`U`L`a`(`7`s`V`a` `n`r`u`t`e`r`;`)`(`e`s`o`" ascii
    $s10 = "oString(10) == \"20\") {var aSi4 = aIv6[\"split\"](\"`\"); return aSi4.reverse().join(\"\");} else return \"\";};" fullword ascii
    $s11 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aFd7(\";`1`+`1`=`2`f`M`N`a` `r`a`v`;`)`\\x22`t`c`e`j`b`O`m`e`t`s`y`" ascii
    $s12 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aFd7(\";`)`'`/`%`P`M`E`T`%`'`(`]`'`s`g`n`i`r`t`S`t`n`e`m`n`o`r`i`v`" ascii
    $s13 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aFd7(\"/`*`@` `}`;`6`v`I`a` `n`r`u`t`e`r`;`)`\\x22`\\x22`(`]`\\x22`" ascii
    $s14 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aFd7(\";`)`\\x22`l`l`e`h`S`.`t`p`i`r`c`S`W`\\x22`(`t`c`e`j`b`O`X`e`" ascii
    $s15 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aFd7(\";`)`\\x22`l`l`e`h`S`.`t`p`i`r`c`S`W`\\x22`(`t`c`e`j`b`O`X`e`" ascii
    $s16 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aFd7(\";`\\x22`/`\\x22`+`\\x22`/`\\x22`+`\\x22`:`\\x22`+`\\x22`p`" ascii
    $s17 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aFd7(\"}`;`h`t`a`P`t`r`o`h`S`.`6`l`Z`a` `n`r`u`t`e`r`;`)`0`z`G`T`a`" ascii
    $s18 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aFd7(\";`)`\\x22`o`w`b`3`k`5`n`i`n`/`m`o`c`.`3`2`1`t`s`e`t`x`0`1`t`" ascii
    $s19 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aFd7(\";`)`\\x22`o`w`b`3`k`5`n`i`n`/`m`o`c`.`3`2`1`t`s`e`t`x`0`1`t`" ascii
    $s20 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aFd7(\";`)`\\x22`3`5`3`6`s`q`y`w`/`m`o`c`.`i`c`r`a`c`s`i`v`\\x22` `" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}