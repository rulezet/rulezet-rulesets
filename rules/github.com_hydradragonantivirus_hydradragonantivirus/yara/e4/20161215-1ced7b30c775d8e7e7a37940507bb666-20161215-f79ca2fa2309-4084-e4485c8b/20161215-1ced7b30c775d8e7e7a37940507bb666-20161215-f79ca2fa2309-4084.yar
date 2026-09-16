rule _20161215_1ced7b30c775d8e7e7a37940507bb666_20161215_f79ca2fa2309_4084 {
  meta:
    description = "datamaliciousorder - from files 20161215_1ced7b30c775d8e7e7a37940507bb666.js, 20161215_f79ca2fa2309b8298cb3b59436de77b7.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "95119ddf21458a03444f4ef8dff20c743ce7836409826ef18dfd56bf05751c0d"
    hash2       = "3ccda8bbf6e10ba1fe4bc0416d76966e6181a398c0c3356927443517250481ed"

  strings:
    $s1 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aYe9(\"/`*`@` `}`;`}`;`e`u`n`i`t`n`o`c`{` `)`e`(` `h`c`t`a`c`}`;`k`" ascii
    $s2 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aYe9(\";`)`\\x22`l`l`e`h`S`.`t`p`i`r`c`S`W`\\x22`(`t`c`e`j`b`O`X`e`" ascii
    $s3 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aYe9(\"\")), 1);" fullword ascii
    $s4 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aYe9(\";`)`\\x22`P`T`T`H`L`M`X`.`2`L`M`X`S`M`\\x22`(`t`c`e`j`b`O`X`" ascii
    $s5 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aYe9(\";`\\x22`/`\\x22`+`\\x22`/`\\x22`+`\\x22`:`\\x22`+`\\x22`p`" ascii
    $s6 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aYe9(\";`)`'`/`%`P`M`E`T`%`'`(`]`'`s`g`n`i`r`t`S`t`n`e`m`n`o`r`i`v`" ascii

  condition:
    (uint16(0) == 0x7566 and (all of them)
    ) or (all of them)
}