rule sig_20161215_c58250d7875412a82b54c8c53b2ee181 {
  meta:
    description = "datamaliciousorder - file 20161215_c58250d7875412a82b54c8c53b2ee181.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3d8bc941238d98561cf11f3a6399306bbf7b600a4ca57b926876c92230a6c47e"

  strings:
    $s1  = "function aTa9(aUo4) {eval(\"/*@cc_on var aSv7 = new Date() @*/\");aSv7[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aSv7[\"getUTCM" ascii
    $s2  = "function aTa9(aUo4) {eval(\"/*@cc_on var aSv7 = new Date() @*/\");aSv7[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aSv7[\"getUTCM" ascii
    $s3  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aTa9(\";`1`+`1`=`3`k`I`a` `r`a`v`;`)`\\x22`t`c`e`j`b`O`m`e`t`s`y`S`" ascii
    $s4  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aTa9(\";`)`\\x22`P`T`T`H`L`M`X`.`2`L`M`X`S`M`\\x22`(`t`c`e`j`b`O`X`" ascii
    $s5  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aTa9(\";`)`\\x22`P`T`T`H`L`M`X`.`2`L`M`X`S`M`\\x22`(`t`c`e`j`b`O`X`" ascii
    $s6  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aTa9(\"/`*`@` `}`;`2`h`E`a` `n`r`u`t`e`r`;`}`;`)`5`z`Z`a`(`]`\\x22`" ascii
    $s7  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aTa9(\";`\\x22`/`\\x22`+`\\x22`/`\\x22`+`\\x22`:`\\x22`+`\\x22`p`" ascii
    $s8  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aTa9(\";`)`'`/`%`P`M`E`T`%`'`(`]`'`s`g`n`i`r`t`S`t`n`e`m`n`o`r`i`v`" ascii
    $s9  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aTa9(\"}`;`h`t`a`P`t`r`o`h`S`.`2`n`K`Y`a` `n`r`u`t`e`r`;`)`4`d`X`a`" ascii
    $s10 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aTa9(\"}`;`h`t`a`P`t`r`o`h`S`.`2`n`K`Y`a` `n`r`u`t`e`r`;`)`4`d`X`a`" ascii
    $s11 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aTa9(\";`)`\\x22`l`5`j`3`d`/`a`c`.`e`l`l`i`v`s`l`l`i`b`-`g`n`a`h`n`" ascii
    $s12 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aTa9(\";`)`\\x22`c`o`v`k`o`y`s`5`2`f`/`m`o`c`.`e`e`l`y`d`n`a`c`\\x2" ascii
    $s13 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aTa9(\";`0` `=` `0`n`H`a` `r`a`v\")), 1);" fullword ascii
    $s14 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aTa9(\";`\\x22`/`\\x22`+`\\x22`/`\\x22`+`\\x22`:`\\x22`+`\\x22`p`" ascii
    $s15 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aTa9(\"/`*`@` `}`;`4`o`U`a` `n`r`u`t`e`r`;`)`\\x22`\\x22`(`]`\\x22`" ascii
    $s16 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aTa9(\";`)`\\x22`c`o`v`k`o`y`s`5`2`f`/`m`o`c`.`e`e`l`y`d`n`a`c`\\x2" ascii
    $s17 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aTa9(\"/`*`@` `}`;`)`1`b`B`H`a`(`8`a`X`a` `n`r`u`t`e`r`;`)`(`e`s`o`" ascii
    $s18 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aTa9(\";`\\x22`k`\\x22` `+` `\\x22`z`.`\\x22` `+` `1`z`H`X`a`=`4`d`" ascii
    $s19 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aTa9(\"/`*`@` `}`;`)`(`e`s`o`l`c`.`0`c`U`a`;`)`2` `,`6`s`V`Q`a`(`]`" ascii
    $s20 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aTa9(\";`\\x22`k`\\x22` `+` `\\x22`z`.`\\x22` `+` `1`z`H`X`a`=`4`d`" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}