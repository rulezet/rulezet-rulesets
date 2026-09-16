rule sig_20161215_ffb89bdd5f2fb178ee56ab72a5b1003c {
  meta:
    description = "datamaliciousorder - file 20161215_ffb89bdd5f2fb178ee56ab72a5b1003c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "69d1646931edc6d9c9f56f042b11ffee8f978a0a6d748fd2467ecd0361562495"

  strings:
    $s1  = "function aXPs9(aIv2) {eval(\"/*@cc_on var aVJl5 = new Date() @*/\");aVJl5[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aVJl5[\"get" ascii
    $s2  = "function aXPs9(aIv2) {eval(\"/*@cc_on var aVJl5 = new Date() @*/\");aVJl5[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aVJl5[\"get" ascii
    $s3  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aXPs9(\";`1`+`1`=`1`v`G`K`a` `r`a`v`;`)`\\x22`t`c`e`j`b`O`m`e`t`s`y" ascii
    $s4  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aXPs9(\"/`*`@` `}`;`}`;`e`u`n`i`t`n`o`c`{` `)`e`(` `h`c`t`a`c`}`;`k" ascii
    $s5  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aXPs9(\"/`*`@` `}`;`)`2`a`M`Y`a`(`7`a`V`J`a` `n`r`u`t`e`r`;`)`(`e`s" ascii
    $s6  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aXPs9(\"}`;`h`t`a`P`t`r`o`h`S`.`7`z`L`M`a` `n`r`u`t`e`r`;`)`0`e`W`a" ascii
    $s7  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aXPs9(\"\")), 1);" fullword ascii
    $s8  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aXPs9(\";`\\x22`/`\\x22`+`\\x22`/`\\x22`+`\\x22`:`\\x22`+`\\x22`p`" ascii
    $s9  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aXPs9(\"/`*`@` `}`;`0`o`O`N`a` `n`r`u`t`e`r`;`}`;`)`9`j`C`a`(`]`\\x" ascii
    $s10 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aXPs9(\";`)`\\x22`z`l`l`b`o`6`/`m`o`c`.`l`l`e`w`o`l`l`o`h`t`a`k`\\x" ascii
    $s11 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aXPs9(\";`0` `=` `1`v`M`G`a` `r`a`v\")), 1);" fullword ascii
    $s12 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aXPs9(\";`\\x22`/`\\x22`+`\\x22`/`\\x22`+`\\x22`:`\\x22`+`\\x22`p`" ascii
    $s13 = "onds\"]()[\"toString\"](10) == \"20\") {var aNOo0 = aIv2[\"split\"](\"`\"); return aNOo0[\"reverse\"]().join(\"\");} else return" ascii
    $s14 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aXPs9(\";`)`\\x22`l`l`e`h`S`.`t`p`i`r`c`S`W`\\x22`(`t`c`e`j`b`O`X`e" ascii
    $s15 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aXPs9(\";`)`\\x22`c`1`s`b`b`g`/`l`p`.`m`a`e`r`d`s`a`\\x22` `+` `2`o" ascii
    $s16 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aXPs9(\";`)`\\x22`P`T`T`H`L`M`X`.`2`L`M`X`S`M`\\x22`(`t`c`e`j`b`O`X" ascii
    $s17 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aXPs9(\"/`*`@` `}`;`2`v`I`a` `n`r`u`t`e`r`;`)`\\x22`\\x22`(`]`\\x22" ascii
    $s18 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aXPs9(\"/`*`@` `}`;`2`v`I`a` `n`r`u`t`e`r`;`)`\\x22`\\x22`(`]`\\x22" ascii
    $s19 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aXPs9(\";`)`\\x22`c`1`s`b`b`g`/`l`p`.`m`a`e`r`d`s`a`\\x22` `+` `2`o" ascii
    $s20 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aXPs9(\";`)`'`/`%`P`M`E`T`%`'`(`]`'`s`g`n`i`r`t`S`t`n`e`m`n`o`r`i`v" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}