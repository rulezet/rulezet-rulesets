rule _20160921_06311313c2c91f30b188be9b0f27e37d_20160921_4a2d69f96df0_1444 {
  meta:
    description = "datamaliciousorder - from files 20160921_06311313c2c91f30b188be9b0f27e37d.js, 20160921_4a2d69f96df0dd4c57fda9e63c804950.js, 20160921_d7492227e681b1689bfc5442a91a169e.js, 20160922_92c62e47426236a3598469915ee3dcfe.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2e8ad2d8de7bc2cc77c2b00b8eeb4fd7976cd68790eeb4b6bfd14ad188696ed0"
    hash2       = "786d4a5233f100c1ba7f5e820c46309247158a45ed43bd58795f05152dbaecf6"
    hash3       = "63aa129680edf69c72e8f077be5e8562f041fa0b0c7e63a8a9b219c23749b135"
    hash4       = "d6b6eb713cecae41143fb04e090a4809564a1837f49e53a84e27f0d3b0885df7"

  strings:
    $s1  = "f000(){return \"GGn\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"I" ascii
    $s2  = "eturn \"GGn\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"Vu\";})()," ascii
    $s3  = "return \"WIj\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"Zj\";})(" ascii
    $s4  = "nction f000(){return \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Nv\";})(),(function f000(){retur" ascii
    $s5  = "ction f000(){return \"Uo\";})(),(function f000(){return \"Nx\";})(),(function f000(){return \"GGn\";})(),(function f000(){return" ascii
    $s6  = "ction f000(){return \"GGn\";})(),(function f000(){return \"Uo\";})(),(function f000(){return \"SEo\";})(),(function f000(){retur" ascii
    $s7  = "rn \"Do\";})(),(function f000(){return \"MKa\";})(),(function f000(){return \"Uo\";})(),(function f000(){return \"SEo\";})(),(fu" ascii
    $s8  = "000(){return \"Oe\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"TRc" ascii
    $s9  = "{return \"Uo\";})(),(function f000(){return \"SEo\";})(),(function f000(){return \"Oh\";})(),(function f000(){return \"MDb\";})(" ascii
    $s10 = "})(),(function f000(){return \"Vu\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"Qz\";})(),(function f000(" ascii
    $s11 = "turn \"GGn\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"Zj\";})()," ascii
    $s12 = "n f000(){return \"Vu\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Q" ascii
    $s13 = ",(function f000(){return \"GGn\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"Zj\";})(),(function f000(){" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}