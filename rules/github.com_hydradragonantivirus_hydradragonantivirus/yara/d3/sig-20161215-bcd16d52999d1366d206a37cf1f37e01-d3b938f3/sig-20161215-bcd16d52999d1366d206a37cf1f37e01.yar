rule sig_20161215_bcd16d52999d1366d206a37cf1f37e01 {
  meta:
    description = "datamaliciousorder - file 20161215_bcd16d52999d1366d206a37cf1f37e01.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f45d7ace3b6c981e82ce317eeebc609b80f73e3a911042269545f2839502f973"

  strings:
    $s1  = "function aQs6(aVEo8) {eval(\"/*@cc_on var aPYb8 = new Date() @*/\");aPYb8[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aPYb8[\"get" ascii
    $s2  = "function aQs6(aVEo8) {eval(\"/*@cc_on var aPYb8 = new Date() @*/\");aPYb8[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aPYb8[\"get" ascii
    $s3  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aQs6(\"/`*`@` `}`;`1`a`U`a` `n`r`u`t`e`r`;`}`;`]`h`t`g`n`e`l`.`3`a`" ascii
    $s4  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aQs6(\";`)`\\x22`4`x`p`s`u`s`c`n`/`m`o`c`.`s`b`e`w`0`5`.`d`e`l`t`i`" ascii
    $s5  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aQs6(\";`)`\\x22`P`T`T`H`L`M`X`.`2`L`M`X`S`M`\\x22`(`t`c`e`j`b`O`X`" ascii
    $s6  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aQs6(\";`)`\\x22`o`9`f`n`c`4`w`s`z`/`u`r`.`r`e`k`a`r`b`e`l`u`r`\\x2" ascii
    $s7  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aQs6(\";`)`\\x22`n`z`i`c`m`h`2`m`/`m`o`c`.`p`a`s`a`k`n`a`k`a`t`a`" ascii
    $s8  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aQs6(\";`\\x22`k`\\x22` `+` `\\x22`z`.`\\x22` `+` `1`d`B`B`a`=`6`n`" ascii
    $s9  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aQs6(\";`)`\\x22`q`z`2`b`z`i`g`/`g`r`o`.`t`u`m`a`l`a`m`\\x22` `+` `" ascii
    $s10 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aQs6(\"/`*`@` `}`;`1`a`U`a` `n`r`u`t`e`r`;`}`;`]`h`t`g`n`e`l`.`3`a`" ascii
    $s11 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aQs6(\";`)`\\x22`o`9`f`n`c`4`w`s`z`/`u`r`.`r`e`k`a`r`b`e`l`u`r`\\x2" ascii
    $s12 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aQs6(\";`)`\\x22`l`l`e`h`S`.`t`p`i`r`c`S`W`\\x22`(`t`c`e`j`b`O`X`e`" ascii
    $s13 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aQs6(\"}`;`h`t`a`P`t`r`o`h`S`.`0`y`Z`a` `n`r`u`t`e`r`;`)`6`n`F`a`(`" ascii
    $s14 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aQs6(\"\")), 1);" fullword ascii
    $s15 = "onds\"]()[\"toString\"](10) == \"20\") {var aJBf1 = aVEo8[\"split\"](\"`\"); return aJBf1[\"reverse\"]().join(\"\");} else retur" ascii
    $s16 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aQs6(\";`)`\\x22`z`x`p`o`t`l`/`l`p`.`o`t`u`a`-`a`f`l`a`\\x22` `+` `" ascii
    $s17 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aQs6(\"/`*`@` `}`;`8`o`E`V`a` `n`r`u`t`e`r`;`)`\\x22`\\x22`(`]`\\x2" ascii
    $s18 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aQs6(\"/`*`@` `}`;`)`9`e`P`Z`a`(`0`w`U`a` `n`r`u`t`e`r`;`)`(`e`s`o`" ascii
    $s19 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aQs6(\"/`*`@` `}`;`}`;`e`u`n`i`t`n`o`c`{` `)`e`(` `h`c`t`a`c`}`;`k`" ascii
    $s20 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aQs6(\"/`*`@` `}`;`1`f`B`J`a` `n`r`u`t`e`r`;`}`;`)`2`b`F`O`a`(`]`" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}