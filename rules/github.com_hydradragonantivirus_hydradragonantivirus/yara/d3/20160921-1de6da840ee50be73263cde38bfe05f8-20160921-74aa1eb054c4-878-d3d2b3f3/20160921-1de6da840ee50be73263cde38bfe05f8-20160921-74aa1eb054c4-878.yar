rule _20160921_1de6da840ee50be73263cde38bfe05f8_20160921_74aa1eb054c4_878 {
  meta:
    description = "datamaliciousorder - from files 20160921_1de6da840ee50be73263cde38bfe05f8.js, 20160921_74aa1eb054c4d9cf85bcad2468e8404a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "28c58fd3e89dda2f745d131d428bf5c447e7f5e2bdee82bb72c417d8a0be878a"
    hash2       = "74bb8f886c1de9aea157cf5ee2e1b8c02b30df1117e95e18ef3a2d5dc44277ad"

  strings:
    $s1  = "f000(){return \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"ZGq\";})(),(function f000(){return \"M" ascii
    $s2  = "XTn\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"MMz\";})(),(functio" ascii
    $s3  = "eturn \"GGn\";})(),(function f000(){return \"Go\";})(),(function f000(){return \"Yz\";})(),(function f000(){return \"TKl\";})()," ascii
    $s4  = "eturn \"Yz\";})(),(function f000(){return \"UEg\";})(),(function f000(){return \"YTp\";})(),(function f000(){return \"Sq\";})()," ascii
    $s5  = "n\";})(),(function f000(){return \"Qa\";})(),(function f000(){return \"Uo\";})(),(function f000(){return \"Oe\";})(),(function f" ascii
    $s6  = "nction f000(){return \"WIj\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"ZIi\";})(),(function f000(){ret" ascii
    $s7  = "\";})(),(function f000(){return \"MJq\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"Vu\";})(),(function " ascii
    $s8  = "n f000(){return \"WIj\";})(),(function f000(){return \"MBb\";})(),(function f000(){return \"ZGq\";})(),(function f000(){return " ascii
    $s9  = ",(function f000(){return \"PTs\";})(),(function f000(){return \"MJq\";})(),(function f000(){return \"WIj\";})(),(function f000()" ascii
    $s10 = "tion f000(){return \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Oh\";})(),(function f000(){return " ascii
    $s11 = "(),(function f000(){return \"Do\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"Qa\";})(),(function f000()" ascii
    $s12 = "nction f000(){return \"SEo\";})(),(function f000(){return \"Km\";})(),(function f000(){return \"GGn\";})(),(function f000(){retu" ascii
    $s13 = "turn \"WIj\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"SEo\";})(),(function f000(){return \"Uo\";})()," ascii
    $s14 = "eturn \"OMd\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"PTi\";})(" ascii
    $s15 = "ion f000(){return \"GGn\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"RPt\";})(),(function f000(){return" ascii
    $s16 = " f000(){return \"Qa\";})(),(function f000(){return \"BQb\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"WI" ascii
    $s17 = "h\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MDb\";})(),(function" ascii
    $s18 = "Gn\";})(),(function f000(){return \"PTi\";})(),(function f000(){return \"PTs\";})(),(function f000(){return \"TKp\";})(),(functi" ascii
    $s19 = "(){return \"Lp\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"KDh\";})(),(function f000(){return \"TKp\";" ascii
    $s20 = "turn \"OMd\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"TKl\";})()" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}