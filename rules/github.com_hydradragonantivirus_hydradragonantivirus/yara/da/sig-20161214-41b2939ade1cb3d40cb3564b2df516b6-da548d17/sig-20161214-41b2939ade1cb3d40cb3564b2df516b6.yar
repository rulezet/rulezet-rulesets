rule sig_20161214_41b2939ade1cb3d40cb3564b2df516b6 {
  meta:
    description = "datamaliciousorder - file 20161214_41b2939ade1cb3d40cb3564b2df516b6.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "72f18ba0c612520ec83e229eb3dc5e205466bc5381921cf837093f46dc0bf935"

  strings:
    $s1  = "function aHp9(aAGh9) {eval(\"/*@cc_on var aKw3 = new Date() @*/\");aKw3[\"setUTCSeconds\"](\"0\", \"20\");if (aKw3.getUTCMillise" ascii
    $s2  = "function aHp9(aAGh9) {eval(\"/*@cc_on var aKw3 = new Date() @*/\");aKw3[\"setUTCSeconds\"](\"0\", \"20\");if (aKw3.getUTCMillise" ascii
    $s3  = "toString(10) == \"20\") {var aKx3 = aAGh9[\"split\"](\"`\"); return aKx3.reverse().join(\"\");} else return \"\";};" fullword ascii
    $s4  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aHp9(\";`)`(`y`a`r`r`A` `w`e`n` `=` `0`u`G`a` `r`a`v` ` ` ` \")), 1" ascii
    $s5  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aHp9(\"/`*`@` `}`;`0`j`Y`a` `n`r`u`t`e`r`;`}`;`]`h`t`g`n`e`l`.`5`j`" ascii
    $s6  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aHp9(\"/`*`@` `}`;`3`x`K`a` `n`r`u`t`e`r`;`}`;`)`2`b`T`a`(`]`\\x22`" ascii
    $s7  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aHp9(\";`)`\\x22`6`t`q`q`x`d`s`u`/`t`e`n`.`s`u`b`c`u`\\x22` `+` `0`" ascii
    $s8  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aHp9(\";`)`\\x22`v`v`6`c`z`a`d`f`u`/`u`r`.`s`t`r`e`s`t`u`o`h`u`b`" ascii
    $s9  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aHp9(\"/`*`@` `}`;`)`(`e`s`o`l`c`.`5`u`N`S`a`;`)`2` `,`8`j`Z`V`a`(`" ascii
    $s10 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aHp9(\";`)`\\x22`v`v`6`c`z`a`d`f`u`/`u`r`.`s`t`r`e`s`t`u`o`h`u`b`" ascii
    $s11 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aHp9(\";`5`m`I`E`a` `+` `3`i`Q`N`a`=`5`q`W`K`a` `r`a`v\")), 1);" fullword ascii
    $s12 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aHp9(\"\")), 1);" fullword ascii
    $s13 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aHp9(\";`\\x22`w`s`m`i`D`j`Z`K`q`8`y`2`l`w`m`3`5`J`v`f`i`i`M`f`s`m`" ascii
    $s14 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aHp9(\";`1`+`1`=`5`l`I`U`a` `r`a`v`;`)`\\x22`t`c`e`j`b`O`m`e`t`s`y`" ascii
    $s15 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aHp9(\";`)`\\x22`3`5`3`6`s`q`y`w`/`m`o`c`.`i`c`r`a`c`s`i`v`\\x22` `" ascii
    $s16 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aHp9(\";`)`\\x22`l`l`e`h`S`.`t`p`i`r`c`S`W`\\x22`(`t`c`e`j`b`O`X`e`" ascii
    $s17 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aHp9(\";`\\x22`/`\\x22`+`\\x22`/`\\x22`+`\\x22`:`\\x22`+`\\x22`p`" ascii
    $s18 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aHp9(\";`)`\\x22`7`o`k`y`5`l`s`/`l`p`.`i`n`h`c`u`k`o`d`o`k`t`s`y`z`" ascii
    $s19 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aHp9(\";`)`\\x22`c`z`6`y`7`u`j`1`w`x`/`g`r`o`.`w`x`a`n`i`h`c`\\x22`" ascii
    $s20 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aHp9(\";`)`\\x22`c`z`6`y`7`u`j`1`w`x`/`g`r`o`.`w`x`a`n`i`h`c`\\x22`" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}