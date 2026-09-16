rule _20160921_523b4f49bbdc4dd92accd0e402a46bfd_20160921_61ffae07802b_563 {
  meta:
    description = "datamaliciousorder - from files 20160921_523b4f49bbdc4dd92accd0e402a46bfd.js, 20160921_61ffae07802bf5013fbbf8f137c827c3.js, 20160921_c1b40d45f00b78160e529a681e4a3e74.js, 20160921_ccabe4fce99c1ebb627aa374a501f33c.js, 20160921_f850d4c4897a9bd959014c9fc7d18a6b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6f9f8d6d5ec4629c30430c47234803f947380ed84d76b2caa48ab30caee473c3"
    hash2       = "d1b5dbd3605683fd0b3b1dc802f1048401a8db23070c8205273f5c5ab6c5133c"
    hash3       = "7f60ab751a30586a95b22cfdbd81084844857ca6374ef9bc8bd4cbdb7cd3cdf9"
    hash4       = "449fe576ee25f77acba5442d771e770819941d7dbf354b5123ca5211ef743189"
    hash5       = "d8fc3e7e41c34088a452b3b6538d4581b58ba00503833e565b195ce374f63b54"

  strings:
    $s1  = "nction f000(){return \"RLk\";})(),(function f000(){return \"DAp\";})(),(function f000(){return \"Wb\";})(),(function f000(){retu" ascii
    $s2  = "(),(function f000(){return \"TKp\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"WIj\";})(),(function f000(" ascii
    $s3  = "n f000(){return \"TKl\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"PTi\";})(),(function f000(){return " ascii
    $s4  = ",(function f000(){return \"MDb\";})(),(function f000(){return \"Nv\";})(),(function f000(){return \"ZIi\";})(),(function f000(){" ascii
    $s5  = ")(),(function f000(){return \"DYs\";})(),(function f000(){return \"Mc\";})(),(function f000(){return \"Qj\";})(),(function f000(" ascii
    $s6  = "ction f000(){return \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Oh\";})(),(function f000(){retur" ascii
    $s7  = "rn \"KDh\";})(),(function f000(){return \"TKp\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"Qa\";})(),(f" ascii
    $s8  = "(){return \"ZFe\";})(),(function f000(){return \"KDh\";})(),(function f000(){return \"Km\";})(),(function f000(){return \"RPt\";" ascii
    $s9  = "00(){return \"Nx\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"Sj\";})(),(function f000(){return \"SEo\"" ascii
    $s10 = "rn \"GGn\";})(),(function f000(){return \"ZIi\";})(),(function f000(){return \"Rh\";})(),(function f000(){return \"Qz\";})(),(fu" ascii
    $s11 = "(),(function f000(){return \"MDb\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"Iq\";})(),(function f000()" ascii
    $s12 = "ction f000(){return \"MDb\";})(),(function f000(){return \"DYs\";})(),(function f000(){return \"Km\";})(),(function f000(){retur" ascii
    $s13 = "){return \"MDb\";})(),(function f000(){return \"Sv\";})(),(function f000(){return \"MBb\";})(),(function f000(){return \"NBs\";}" ascii
    $s14 = " f000(){return \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Qa\";})(),(function f000(){return \"Uo" ascii
    $s15 = " f000(){return \"MDb\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"UEg\";})(),(function f000(){return \"L" ascii
    $s16 = "ction f000(){return \"Oh\";})(),(function f000(){return \"DYx\";})(),(function f000(){return \"TKl\";})(),(function f000(){retur" ascii
    $s17 = "Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Yv\";})(),(function f000(){return \"SEo\";})(),(functio" ascii
    $s18 = "ion f000(){return \"Sj\";})(),(function f000(){return \"MBb\";})(),(function f000(){return \"YTp\";})(),(function f000(){return " ascii
    $s19 = "{return \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"PTs\";})(),(function f000(){return \"MJq\";})" ascii
    $s20 = "nction f000(){return \"Yv\";})(),(function f000(){return \"Nx\";})(),(function f000(){return \"MDb\";})(),(function f000(){retur" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}