rule _20160921_06311313c2c91f30b188be9b0f27e37d_20160921_1c5a439961f0_1645 {
  meta:
    description = "datamaliciousorder - from files 20160921_06311313c2c91f30b188be9b0f27e37d.js, 20160921_1c5a439961f0eccee5312fdbb892fb0e.js, 20160921_4a2d69f96df0dd4c57fda9e63c804950.js, 20160922_92c62e47426236a3598469915ee3dcfe.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2e8ad2d8de7bc2cc77c2b00b8eeb4fd7976cd68790eeb4b6bfd14ad188696ed0"
    hash2       = "3fbb744f5c370c0fc7398db52f2d758d4ee9e8aaf91430daa5c6bada9598710f"
    hash3       = "786d4a5233f100c1ba7f5e820c46309247158a45ed43bd58795f05152dbaecf6"
    hash4       = "d6b6eb713cecae41143fb04e090a4809564a1837f49e53a84e27f0d3b0885df7"

  strings:
    $s1  = "){return \"WIj\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"GGn\";}" ascii
    $s2  = "n f000(){return \"TKl\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"TRc\";})(),(function f000(){return " ascii
    $s3  = "eturn \"GGn\";})(),(function f000(){return \"ZIi\";})(),(function f000(){return \"RVb\";})(),(function f000(){return \"GGn\";})(" ascii
    $s4  = "0(){return \"BIj\";})(),(function f000(){return \"KDh\";})(),(function f000(){return \"SEo\";})(),(function f000(){return \"NBs" ascii
    $s5  = "(),(function f000(){return \"Lp\";})(),(function f000(){return \"Sv\";})(),(function f000(){return \"NBs\";})(),(function f000()" ascii
    $s6  = "ion f000(){return \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"IAa\";})(),(function f000(){return" ascii
    $s7  = ")(),(function f000(){return \"KXg\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"GGn\";})(),(function f000" ascii
    $s8  = "),(function f000(){return \"Nv\";})(),(function f000(){return \"Sj\";})(),(function f000(){return \"UEg\";})(),(function f000(){" ascii
    $s9  = "(){return \"GGn\";})(),(function f000(){return \"Qp\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Wb\";}" ascii
    $s10 = "00(){return \"SEo\";})(),(function f000(){return \"Iq\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"Ml\"" ascii
    $s11 = "urn \"Vu\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"GGn\";})(),(" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}