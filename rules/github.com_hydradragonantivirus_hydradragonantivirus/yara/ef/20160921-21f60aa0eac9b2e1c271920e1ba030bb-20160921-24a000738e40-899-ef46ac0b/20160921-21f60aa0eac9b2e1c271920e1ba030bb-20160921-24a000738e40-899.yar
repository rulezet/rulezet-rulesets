rule _20160921_21f60aa0eac9b2e1c271920e1ba030bb_20160921_24a000738e40_899 {
  meta:
    description = "datamaliciousorder - from files 20160921_21f60aa0eac9b2e1c271920e1ba030bb.js, 20160921_24a000738e40009c8bea0a81a0c09cf4.js, 20160921_67c50b9dab5bb43a7f01552ab820f46c.js, 20160921_8471da3d602dedb9a4749d6e2c757b47.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d62e554404acfef03995a5bdd7d29935f7247fd9707d5ea364fac80fddc940f7"
    hash2       = "f61bde20fd51cb3330f21d75680b7197049050166838d3ae36cae4b7521bfd50"
    hash3       = "95b498a0f19ae8b7e9793e4cb9042b95bb6ba62738825d4cc0684c4bbb8a3d9d"
    hash4       = "98a5a561c128a716a07f6503ae8144cb9404c06eb1a2796af84924653c81967c"

  strings:
    $s1  = "ion f000(){return \"GGn\";})(),(function f000(){return \"Qa\";})(),(function f000(){return \"Uo\";})(),(function f000(){return " ascii
    $s2  = "unction f000(){return \"BQb\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"MDb\";})(),(function f000(){ret" ascii
    $s3  = "n \"TKl\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"MBb\";})(),(function f000(){return \"ZGq\";})(),(f" ascii
    $s4  = "0(){return \"GGn\";})(),(function f000(){return \"PTs\";})(),(function f000(){return \"MJq\";})(),(function f000(){return \"WIj" ascii
    $s5  = "000(){return \"PTs\";})(),(function f000(){return \"DYs\";})(),(function f000(){return \"Mc\";})(),(function f000(){return \"Qj" ascii
    $s6  = "tion f000(){return \"MDb\";})(),(function f000(){return \"Yv\";})(),(function f000(){return \"EZu\";})(),(function f000(){return" ascii
    $s7  = "Ts\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"IPu\";})(),(function f000(){return \"OMd\";})(),(functio" ascii
    $s8  = "s\";})(),(function f000(){return \"Mc\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"GGn\";})(),(function " ascii
    $s9  = "n\";})(),(function f000(){return \"SEo\";})(),(function f000(){return \"ZIi\";})(),(function f000(){return \"BMj\";})(),(functio" ascii
    $s10 = "\"UEg\";})(),(function f000(){return \"OMd\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"ZFe\";})(),(fun" ascii
    $s11 = ";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"Sq\";})(),(function f000(){return \"RPt\";})(),(function f0" ascii
    $s12 = "urn \"RPt\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Mu\";})(),(f" ascii
    $s13 = "return \"NYh\";})(),(function f000(){return \"DIa\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"MMz\";})(" ascii
    $s14 = "f000(){return \"Wb\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"Qa" ascii
    $s15 = "){return \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"KDh\";})(),(function f000(){return \"Yv\";}" ascii
    $s16 = "\"BMj\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MDb\";})(),(func" ascii
    $s17 = "{return \"MDb\";})(),(function f000(){return \"KDh\";})(),(function f000(){return \"Qa\";})(),(function f000(){return \"UEg\";})" ascii
    $s18 = "000(){return \"ZIi\";})(),(function f000(){return \"Nx\";})(),(function f000(){return \"OMd\";})(),(function f000(){return \"GGn" ascii
    $s19 = "rn \"GGn\";})(),(function f000(){return \"ZGq\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"NYh\";})(),(" ascii
    $s20 = "on f000(){return \"YTp\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"IAa\";})(),(function f000(){return " ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}