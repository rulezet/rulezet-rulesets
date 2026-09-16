rule _20160921_23ef471e720525eb3dff80c2296d1a60_20160921_74aa1eb054c4_391 {
  meta:
    description = "datamaliciousorder - from files 20160921_23ef471e720525eb3dff80c2296d1a60.js, 20160921_74aa1eb054c4d9cf85bcad2468e8404a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b0945c221a3a5ff2958847eac00c479ff3a9b1c8dd949684148aca0eeaf3afeb"
    hash2       = "74bb8f886c1de9aea157cf5ee2e1b8c02b30df1117e95e18ef3a2d5dc44277ad"

  strings:
    $s1  = "turn \"Yi\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"TRc\";})(),(" ascii
    $s2  = "function f000(){return \"GGn\";})(),(function f000(){return \"ZGq\";})(),(function f000(){return \"PTs\";})(),(function f000(){r" ascii
    $s3  = "nction f000(){return \"Qj\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"GGn\";})(),(function f000(){retu" ascii
    $s4  = "\"Kw\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"TRc\";})(),(funct" ascii
    $s5  = "00(){return \"OUx\";})(),(function f000(){return \"Mu\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"Qj\";" ascii
    $s6  = "\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"Qj\";})(),(function f0" ascii
    $s7  = "urn \"Qj\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"Qz\";})(),(fu" ascii
    $s8  = "(){return \"Sj\";})(),(function f000(){return \"NBs\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"WIj\";" ascii
    $s9  = "Mu\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"Lp\";})(),(function" ascii
    $s10 = "nction f000(){return \"RPt\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"Zj\";})(),(function f000(){retur" ascii
    $s11 = "(){return \"WIj\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"Kw\";}" ascii
    $s12 = "0(){return \"Qz\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"MMz\";}" ascii
    $s13 = ";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"Lp\";})(),(function f00" ascii
    $s14 = ")(),(function f000(){return \"Do\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"XTn\";})(),(function f000(" ascii
    $s15 = " \"WIj\";})(),(function f000(){return \"Oh\";})(),(function f000(){return \"ZIi\";})(),(function f000(){return \"NBs\";})(),(fun" ascii
    $s16 = "Qj\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"TRc\";})(),(functio" ascii
    $s17 = "eturn \"TRc\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"Yi\";})()" ascii
    $s18 = " \"OUx\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"Qj\";})(),(funct" ascii
    $s19 = "tion f000(){return \"TKl\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"Yi\";})(),(function f000(){return " ascii
    $s20 = "n \"Kw\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"TRc\";})(),(fun" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}