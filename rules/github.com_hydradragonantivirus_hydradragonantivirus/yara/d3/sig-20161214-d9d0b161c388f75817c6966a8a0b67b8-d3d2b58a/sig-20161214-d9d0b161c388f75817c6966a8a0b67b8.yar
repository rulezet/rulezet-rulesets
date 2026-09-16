rule sig_20161214_d9d0b161c388f75817c6966a8a0b67b8 {
  meta:
    description = "datamaliciousorder - file 20161214_d9d0b161c388f75817c6966a8a0b67b8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "10a23b04454aa5a6df896c4cf21e824c7fa334b86922ec58d82becbb305bdc12"

  strings:
    $s1  = "function aDq6(aAUx3) {eval(\"/*@cc_on var aXHq6 = new Date() @*/\");aXHq6[\"setUTCSeconds\"](\"0\", \"20\");if (aXHq6.getUTCMill" ascii
    $s2  = "function aDq6(aAUx3) {eval(\"/*@cc_on var aXHq6 = new Date() @*/\");aXHq6[\"setUTCSeconds\"](\"0\", \"20\");if (aXHq6.getUTCMill" ascii
    $s3  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aDq6(\";`1`+`1`=`5`e`K`R`a` `r`a`v`;`)`\\x22`t`c`e`j`b`O`m`e`t`s`y`" ascii
    $s4  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aDq6(\";`)`\\x22`s`x`t`r`w`o`i`l`/`t`p`.`k`a`e`p`s`u`o`y`\\x22` `+`" ascii
    $s5  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aDq6(\"/`*`@` `}`;`8`a`P`D`a` `n`r`u`t`e`r`;`}`;`)`3`k`E`Q`a`(`]`" ascii
    $s6  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aDq6(\";`\\x22`k`\\x22` `+` `\\x22`z`.`\\x22` `+` `0`z`T`a`=`3`n`W`" ascii
    $s7  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aDq6(\"/`*`@` `}`;`}`;`e`u`n`i`t`n`o`c`{` `)`e`(` `h`c`t`a`c`}`;`k`" ascii
    $s8  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aDq6(\";`1`+`1`=`5`e`K`R`a` `r`a`v`;`)`\\x22`t`c`e`j`b`O`m`e`t`s`y`" ascii
    $s9  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aDq6(\"/`*`@` `}`;`9`t`Z`S`a` `n`r`u`t`e`r`;`}`;`]`h`t`g`n`e`l`.`4`" ascii
    $s10 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aDq6(\"\")), 1);" fullword ascii
    $s11 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aDq6(\"/`*`@` `}`;`)`(`e`s`o`l`c`.`0`v`Z`a`;`)`2` `,`4`m`K`a`(`]`" ascii
    $s12 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aDq6(\";`)`\\x22`f`g`s`i`n`b`7`/`z`c`.`k`a`l`m`u`h`.`4`6`n`a`m`o`r`" ascii
    $s13 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aDq6(\"/`*`@` `}`;`3`x`U`A`a` `n`r`u`t`e`r`;`)`\\x22`\\x22`(`]`\\x2" ascii
    $s14 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aDq6(\";`)`\\x22`u`4`2`k`j`z`z`w`8`/`i`a`1`p`-`-`n`x`.`e`f`e`f`f`a`" ascii
    $s15 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aDq6(\";`)`\\x22`f`g`s`i`n`b`7`/`z`c`.`k`a`l`m`u`h`.`4`6`n`a`m`o`r`" ascii
    $s16 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aDq6(\"}`;`h`t`a`P`t`r`o`h`S`.`0`v`R`a` `n`r`u`t`e`r`;`)`3`n`W`a`(`" ascii
    $s17 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aDq6(\";`)`\\x22`p`c`6`k`7`/`u`r`.`t`s`u`d`-`i`t`n`a`\\x22` `+` `8`" ascii
    $s18 = "().toString(10) == \"20\") {var aDPa8 = aAUx3[\"split\"](\"`\"); return aDPa8.reverse().join(\"\");} else return \"\";};" fullword ascii
    $s19 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aDq6(\";`)`'`/`%`P`M`E`T`%`'`(`]`'`s`g`n`i`r`t`S`t`n`e`m`n`o`r`i`v`" ascii
    $s20 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aDq6(\";`)`\\x22`s`x`t`r`w`o`i`l`/`t`p`.`k`a`e`p`s`u`o`y`\\x22` `+`" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}