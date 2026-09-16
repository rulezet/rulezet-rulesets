rule _20160921_06311313c2c91f30b188be9b0f27e37d_20160921_4a2d69f96df0_2653 {
  meta:
    description = "datamaliciousorder - from files 20160921_06311313c2c91f30b188be9b0f27e37d.js, 20160921_4a2d69f96df0dd4c57fda9e63c804950.js, 20160921_7cd473b59463126782b9a6cfaae72835.js, 20160922_92c62e47426236a3598469915ee3dcfe.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2e8ad2d8de7bc2cc77c2b00b8eeb4fd7976cd68790eeb4b6bfd14ad188696ed0"
    hash2       = "786d4a5233f100c1ba7f5e820c46309247158a45ed43bd58795f05152dbaecf6"
    hash3       = "0e3e3663f9696265255bc848bc98ec77487c491ee2a30b3085dbc10087b935c5"
    hash4       = "d6b6eb713cecae41143fb04e090a4809564a1837f49e53a84e27f0d3b0885df7"

  strings:
    $s1 = "return \"OUx\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"Qz\";})()" ascii
    $s2 = "Vu\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"Vj\";})(),(function" ascii
    $s3 = " f000(){return \"OUx\";})(),(function f000(){return \"Uo\";})(),(function f000(){return \"MJq\";})(),(function f000(){return \"V" ascii
    $s4 = " \"OUx\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"XTn\";})(),(fun" ascii
    $s5 = "000(){return \"OUx\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"Vu" ascii
    $s6 = "n \"Yv\";})(),(function f000(){return \"Yv\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"GGn\";})(),(func" ascii
    $s7 = "){return \"KXg\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"KXg\";})" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}