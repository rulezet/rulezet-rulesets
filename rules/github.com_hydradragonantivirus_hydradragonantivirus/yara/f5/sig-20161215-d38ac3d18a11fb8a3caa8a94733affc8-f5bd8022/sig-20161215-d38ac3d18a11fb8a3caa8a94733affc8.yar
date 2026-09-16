rule sig_20161215_d38ac3d18a11fb8a3caa8a94733affc8 {
  meta:
    description = "datamaliciousorder - file 20161215_d38ac3d18a11fb8a3caa8a94733affc8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "554ef234323f9b9d0793dc83c4f24da9614a9b464e53d9fa4946ecdc0149fe83"

  strings:
    $s1  = "function aGv2(aQc3) {eval(\"/*@cc_on var aEBa6 = new Date() @*/\");aEBa6[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aEBa6[\"getU" ascii
    $s2  = "function aGv2(aQc3) {eval(\"/*@cc_on var aEBa6 = new Date() @*/\");aEBa6[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aEBa6[\"getU" ascii
    $s3  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aGv2(\"/`*`@` `}`;`3`c`Q`a` `n`r`u`t`e`r`;`)`\\x22`\\x22`(`]`\\x22`" ascii
    $s4  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aGv2(\";`)`\\x22`l`m`n`5`n`6`q`/`m`o`c`.`i`h`s`u`o`b`a`m`a`y`o`n`o`" ascii
    $s5  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aGv2(\"}`;`h`t`a`P`t`r`o`h`S`.`8`h`O`a` `n`r`u`t`e`r`;`)`9`z`Z`H`a`" ascii
    $s6  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aGv2(\";`\\x22`/`\\x22`+`\\x22`/`\\x22`+`\\x22`:`\\x22`+`\\x22`p`" ascii
    $s7  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aGv2(\";`)`\\x22`c`z`6`y`7`u`j`1`w`x`/`m`o`c`.`e`k`a`w`n`a`c`i`r`e`" ascii
    $s8  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aGv2(\";`)`\\x22`k`p`i`p`n`o`y`8`9`q`/`n`c`.`c`i`m`2`7`\\x22` `+` `" ascii
    $s9  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aGv2(\";`0` `=` `2`a`V`X`a` `r`a`v\")), 1);" fullword ascii
    $s10 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aGv2(\"/`*`@` `}`;`}`;`e`u`n`i`t`n`o`c`{` `)`e`(` `h`c`t`a`c`}`;`k`" ascii
    $s11 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aGv2(\";`)`\\x22`l`l`e`h`S`.`t`p`i`r`c`S`W`\\x22`(`t`c`e`j`b`O`X`e`" ascii
    $s12 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aGv2(\";`)`\\x22`x`i`1`5`x`c`y`u`/`m`o`c`.`e`l`b`u`o`d`n`i`a`r`b`" ascii
    $s13 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aGv2(\"/`*`@` `}`;`)`8`y`E`X`a`(`7`v`E`a` `n`r`u`t`e`r`;`)`(`e`s`o`" ascii
    $s14 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aGv2(\";`1`+`1`=`1`f`M`a` `r`a`v`;`)`\\x22`t`c`e`j`b`O`m`e`t`s`y`S`" ascii
    $s15 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aGv2(\";`)`\\x22`l`l`e`h`S`.`t`p`i`r`c`S`W`\\x22`(`t`c`e`j`b`O`X`e`" ascii
    $s16 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aGv2(\"/`*`@` `}`;`)`8`y`E`X`a`(`7`v`E`a` `n`r`u`t`e`r`;`)`(`e`s`o`" ascii
    $s17 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aGv2(\"/`*`@` `}`;`)`(`e`s`o`l`c`.`1`d`W`a`;`)`2` `,`1`q`H`a`(`]`" ascii
    $s18 = "nds\"]()[\"toString\"](10) == \"20\") {var aNg9 = aQc3[\"split\"](\"`\"); return aNg9[\"reverse\"]().join(\"\");} else return \"" ascii
    $s19 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aGv2(\";`)`\\x22`k`p`i`p`n`o`y`8`9`q`/`n`c`.`c`i`m`2`7`\\x22` `+` `" ascii
    $s20 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aGv2(\";`)`\\x22`g`r`f`q`w`x`k`p`/`m`o`c`.`s`b`e`w`0`5`.`k`o`o`b`" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}