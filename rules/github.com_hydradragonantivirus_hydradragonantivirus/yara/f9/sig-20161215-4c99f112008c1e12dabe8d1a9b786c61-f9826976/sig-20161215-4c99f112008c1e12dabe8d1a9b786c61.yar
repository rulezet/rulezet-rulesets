rule sig_20161215_4c99f112008c1e12dabe8d1a9b786c61 {
  meta:
    description = "datamaliciousorder - file 20161215_4c99f112008c1e12dabe8d1a9b786c61.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b2692d9634ad841c6385edfd03389ba26ca5a53bfdc037bc061b42d347b2bb36"

  strings:
    $s1  = "function aPKc3(aIKo8) {eval(\"/*@cc_on var aLZq6 = new Date() @*/\");aLZq6[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aLZq6[\"ge" ascii
    $s2  = "function aPKc3(aIKo8) {eval(\"/*@cc_on var aLZq6 = new Date() @*/\");aLZq6[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aLZq6[\"ge" ascii
    $s3  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aPKc3(\";`)`\\x22`1`s`j`d`t`y`0`/`g`r`o`.`e`n`i`l`n`o`p`a`h`p`i`a`i" ascii
    $s4  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aPKc3(\"/`*`@` `}`;`)`(`e`s`o`l`c`.`2`w`G`B`a`;`)`2` `,`3`z`W`a`(`]" ascii
    $s5  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aPKc3(\"/`*`@` `}`;`7`e`U`H`a` `n`r`u`t`e`r`;`}`;`]`h`t`g`n`e`l`.`0" ascii
    $s6  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aPKc3(\";`)`(`y`a`r`r`A` `w`e`n` `=` `4`w`N`a` `r`a`v` ` ` ` \")), " ascii
    $s7  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aPKc3(\"/`*`@` `}`;`7`e`U`H`a` `n`r`u`t`e`r`;`}`;`]`h`t`g`n`e`l`.`0" ascii
    $s8  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aPKc3(\";`1`+`1`=`5`q`S`C`a` `r`a`v`;`)`\\x22`t`c`e`j`b`O`m`e`t`s`y" ascii
    $s9  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aPKc3(\"/`*`@` `}`;`8`f`G`a` `n`r`u`t`e`r`;`}`;`)`1`y`U`K`a`(`]`\\x" ascii
    $s10 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aPKc3(\";`\\x22`k`\\x22` `+` `\\x22`z`.`\\x22` `+` `0`h`W`I`a`=`3`t" ascii
    $s11 = "conds\"]()[\"toString\"](10) == \"20\") {var aGf8 = aIKo8[\"split\"](\"`\"); return aGf8[\"reverse\"]().join(\"\");} else return" ascii
    $s12 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aPKc3(\";`)`\\x22`3`p`3`p`s`0`w`q`q`y`/`m`o`c`.`a`n`i`m`u`l`a`-`o`e" ascii
    $s13 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aPKc3(\";`)`\\x22`1`s`j`d`t`y`0`/`g`r`o`.`e`n`i`l`n`o`p`a`h`p`i`a`i" ascii
    $s14 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aPKc3(\";`\\x22`i`J`o`b`R`G`U`A`N`\\x22` `=` `8`g`K`a` `r`a`v` `;`" ascii
    $s15 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aPKc3(\"/`*`@` `}`;`}`;`e`u`n`i`t`n`o`c`{` `)`e`(` `h`c`t`a`c`}`;`k" ascii
    $s16 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aPKc3(\"/`*`@` `}`;`8`o`K`I`a` `n`r`u`t`e`r`;`)`\\x22`\\x22`(`]`\\x" ascii
    $s17 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aPKc3(\"\")), 1);" fullword ascii
    $s18 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aPKc3(\";`)`\\x22`g`i`d`d`1`/`u`r`.`o`n`i`j`y`m`.`8`8`c`i`l`o`r`c`" ascii
    $s19 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aPKc3(\"/`*`@` `}`;`)`1`u`S`a`(`7`s`N`Q`a` `n`r`u`t`e`r`;`)`(`e`s`o" ascii
    $s20 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aPKc3(\";`)`\\x22`2`b`m`u`k`r`5`/`m`o`c`.`u`4`h`2`\\x22` `+` `5`p`U" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}