rule _20160921_06311313c2c91f30b188be9b0f27e37d_20160921_4a2d69f96df0_3253 {
  meta:
    description = "datamaliciousorder - from files 20160921_06311313c2c91f30b188be9b0f27e37d.js, 20160921_4a2d69f96df0dd4c57fda9e63c804950.js, 20160921_5d76de82063e28ac2a0fc9a6ce296761.js, 20160922_92c62e47426236a3598469915ee3dcfe.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2e8ad2d8de7bc2cc77c2b00b8eeb4fd7976cd68790eeb4b6bfd14ad188696ed0"
    hash2       = "786d4a5233f100c1ba7f5e820c46309247158a45ed43bd58795f05152dbaecf6"
    hash3       = "4e44228eb55ff969128759659f37a0c5ebdeb5fc653b3b206ba5fa42d8e30166"
    hash4       = "d6b6eb713cecae41143fb04e090a4809564a1837f49e53a84e27f0d3b0885df7"

  strings:
    $s1 = "\";})(),(function f000(){return \"TKp\";})(),(function f000(){return \"Lo\";})(),(function f000(){return \"Iq\";})(),(function f" ascii
    $s2 = "00(){return \"Ml\";})(),(function f000(){return \"Nv\";})(),(function f000(){return \"NBs\";})(),(function f000(){return \"Mc\";" ascii
    $s3 = "eturn \"Tn\";})(),(function f000(){return \"DYx\";})(),(function f000(){return \"TKp\";})(),(function f000(){return \"MJq\";})()" ascii
    $s4 = "nction f000(){return \"Yz\";})(),(function f000(){return \"TKp\";})(),(function f000(){return \"YTp\";})(),(function f000(){retu" ascii
    $s5 = " \"TKp\";})(),(function f000(){return \"IPu\";})(),(function f000(){return \"UEg\";})(),(function f000(){return \"QDg\";})(),(fu" ascii
    $s6 = "on f000(){return \"Oe\";})(),(function f000(){return \"TKp\";})(),(function f000(){return \"Wy\";})(),(function f000(){return \"" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}