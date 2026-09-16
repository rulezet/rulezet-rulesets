rule sig_20161215_07dbe6eb76fe0abff82a079ee3b02a2f {
  meta:
    description = "datamaliciousorder - file 20161215_07dbe6eb76fe0abff82a079ee3b02a2f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c1a593983e4cbdbefaee8218097bd8ec893e7165539bcec00d151279a8fb74dc"

  strings:
    $s1  = "function aWn0(aBOi6) {eval(\"/*@cc_on var aYk6 = new Date() @*/\");aYk6[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aYk6[\"getUTC" ascii
    $s2  = "function aWn0(aBOi6) {eval(\"/*@cc_on var aYk6 = new Date() @*/\");aYk6[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aYk6[\"getUTC" ascii
    $s3  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aWn0(\";`1`+`1`=`0`c`D`a` `r`a`v`;`)`\\x22`t`c`e`j`b`O`m`e`t`s`y`S`" ascii
    $s4  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aWn0(\";`\\x22`/`\\x22`+`\\x22`/`\\x22`+`\\x22`:`\\x22`+`\\x22`p`" ascii
    $s5  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aWn0(\"/`*`@` `}`;`)`(`e`s`o`l`c`.`4`w`B`I`a`;`)`2` `,`0`c`N`a`(`]`" ascii
    $s6  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aWn0(\";`)`\\x22`q`j`s`v`b`/`m`o`c`.`e`r`a`p`s`i`h`s`.`o`m`e`d`\\x2" ascii
    $s7  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aWn0(\";`)`\\x22`p`h`c`y`l`a`h`l`d`/`d`i`.`o`g`.`b`a`k`a`y`a`r`s`a`" ascii
    $s8  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aWn0(\";`)`'`/`%`P`M`E`T`%`'`(`]`'`s`g`n`i`r`t`S`t`n`e`m`n`o`r`i`v`" ascii
    $s9  = "s\"]()[\"toString\"](10) == \"20\") {var aJy4 = aBOi6[\"split\"](\"`\"); return aJy4[\"reverse\"]().join(\"\");} else return \"" ascii
    $s10 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aWn0(\"/`*`@` `}`;`4`y`J`a` `n`r`u`t`e`r`;`}`;`)`4`r`F`a`(`]`\\x22`" ascii
    $s11 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aWn0(\";`)`\\x22`1`t`j`m`g`a`3`/`m`o`c`.`b`l`-`e`c`i`f`f`o`r`e`t`n`" ascii
    $s12 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aWn0(\"/`*`@` `}`;`6`i`O`B`a` `n`r`u`t`e`r`;`)`\\x22`\\x22`(`]`\\x2" ascii
    $s13 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aWn0(\"/`*`@` `}`;`)`(`e`s`o`l`c`.`4`w`B`I`a`;`)`2` `,`0`c`N`a`(`]`" ascii
    $s14 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aWn0(\"/`*`@` `}`;`}`;`e`u`n`i`t`n`o`c`{` `)`e`(` `h`c`t`a`c`}`;`k`" ascii
    $s15 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aWn0(\"}`;`h`t`a`P`t`r`o`h`S`.`9`w`H`a` `n`r`u`t`e`r`;`)`6`e`G`Q`a`" ascii
    $s16 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aWn0(\"/`*`@` `}`;`}`;`e`u`n`i`t`n`o`c`{` `)`e`(` `h`c`t`a`c`}`;`k`" ascii
    $s17 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aWn0(\";`)`\\x22`f`a`w`b`p`j`0`/`r`k`.`o`c`.`t`s`u`r`t`g`i`b`\\x22`" ascii
    $s18 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aWn0(\";`)`'`/`%`P`M`E`T`%`'`(`]`'`s`g`n`i`r`t`S`t`n`e`m`n`o`r`i`v`" ascii
    $s19 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aWn0(\";`)`\\x22`p`q`1`y`r`x`2`/`m`o`c`.`r`a`e`w`r`e`f`a`l`\\x22` `" ascii
    $s20 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aWn0(\"/`*`@` `}`;`4`y`J`a` `n`r`u`t`e`r`;`}`;`)`4`r`F`a`(`]`\\x22`" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}