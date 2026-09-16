rule sig_20161214_4537337d4840d83bf4852dc8b0995b95 {
  meta:
    description = "datamaliciousorder - file 20161214_4537337d4840d83bf4852dc8b0995b95.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d8ec3c1031c412945e5126af0e8aa0d23acac745471d3b38299bb50c7ffe32db"

  strings:
    $s1  = "function aYEe5(aMl0) {eval(\"/*@cc_on var aWFe7 = new Date() @*/\");aWFe7[\"setUTCSeconds\"](\"0\", \"20\");if (aWFe7.getUTCMill" ascii
    $s2  = "function aYEe5(aMl0) {eval(\"/*@cc_on var aWFe7 = new Date() @*/\");aWFe7[\"setUTCSeconds\"](\"0\", \"20\");if (aWFe7.getUTCMill" ascii
    $s3  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aYEe5(\"}`;`h`t`a`P`t`r`o`h`S`.`1`c`V`a` `n`r`u`t`e`r`;`)`6`m`M`a`(" ascii
    $s4  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aYEe5(\";`)`\\x22`e`k`s`9`j`6`g`j`m`k`/`m`o`c`.`n`o`w`i`n`-`u`\\x22" ascii
    $s5  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aYEe5(\";`\\x22`w`s`m`i`D`j`Z`K`q`8`y`2`l`w`m`3`5`J`v`f`i`i`M`f`s`m" ascii
    $s6  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aYEe5(\";`\\x22`/`\\x22`+`\\x22`/`\\x22`+`\\x22`:`\\x22`+`\\x22`p`" ascii
    $s7  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aYEe5(\"}`;`h`t`a`P`t`r`o`h`S`.`1`c`V`a` `n`r`u`t`e`r`;`)`6`m`M`a`(" ascii
    $s8  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aYEe5(\";`)`\\x22`f`s`a`j`v`d`6`/`m`o`c`.`h`n`i`d`y`m`e`m`o`h`n`i`v" ascii
    $s9  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aYEe5(\"/`*`@` `}`;`3`u`E`a` `n`r`u`t`e`r`;`}`;`]`h`t`g`n`e`l`.`1`n" ascii
    $s10 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aYEe5(\"/`*`@` `}`;`0`x`Y`Z`a` `n`r`u`t`e`r`;`}`;`)`7`v`Y`a`(`]`\\x" ascii
    $s11 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aYEe5(\";`)`\\x22`e`k`s`9`j`6`g`j`m`k`/`m`o`c`.`n`o`w`i`n`-`u`\\x22" ascii
    $s12 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aYEe5(\";`)`\\x22`f`g`s`i`n`b`7`/`z`c`.`k`a`l`m`u`h`.`4`6`n`a`m`o`r" ascii
    $s13 = "().toString(10) == \"20\") {var aZYx0 = aMl0[\"split\"](\"`\"); return aZYx0.reverse().join(\"\");} else return \"\";};" fullword ascii
    $s14 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aYEe5(\"/`*`@` `}`;`}`;`e`u`n`i`t`n`o`c`{` `)`e`(` `h`c`t`a`c`}`;`k" ascii
    $s15 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aYEe5(\";`)`\\x22`l`l`e`h`S`.`t`p`i`r`c`S`W`\\x22`(`t`c`e`j`b`O`X`e" ascii
    $s16 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aYEe5(\";`\\x22`k`\\x22` `+` `\\x22`z`.`\\x22` `+` `4`k`T`T`a`=`6`m" ascii
    $s17 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aYEe5(\";`)`\\x22`f`s`a`j`v`d`6`/`m`o`c`.`h`n`i`d`y`m`e`m`o`h`n`i`v" ascii
    $s18 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aYEe5(\";`)`\\x22`p`c`6`k`7`/`u`r`.`t`s`u`d`-`i`t`n`a`\\x22` `+` `7" ascii
    $s19 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aYEe5(\";`)`\\x22`x`m`v`n`y`j`/`.`m`o`c`.`b`s`0`5`2`\\x22` `+` `7`r" ascii
    $s20 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aYEe5(\"/`*`@` `}`;`0`x`Y`Z`a` `n`r`u`t`e`r`;`}`;`)`7`v`Y`a`(`]`\\x" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}