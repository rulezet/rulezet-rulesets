rule _20160921_4319d62667a3ba06f88c6ba9123c871b_20160921_7ffe38e0972c_3709 {
  meta:
    description = "datamaliciousorder - from files 20160921_4319d62667a3ba06f88c6ba9123c871b.js, 20160921_7ffe38e0972c323071684bfa98cafbdf.js, 20160921_eba3e9dc8ad614a7e5c422a93cd7b424.js, 20160922_51694f0251fa3f1d7267b3d7973d4097.js, 20160922_abb8cfe456777bb23f3253a5921340d2.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "33e5babd254cb93078c026ebb6beb245e487651597122eb576cf5b870dfbf8ee"
    hash2       = "4bc751383d4c72f88b3f59d9fde1f38f09a81b77ee4df0498bec1df7cd088bc7"
    hash3       = "f0f6c6f4fe3daf7aae3b8d7276adbcc6577a8bf844eeae945023523b63b6cc9a"
    hash4       = "c424926fb99cca3faf3dda68a4860b770a7f0467803b01fbdf54011c52f56a99"
    hash5       = "658f6872a894eb9bcb193b7bf73260e92d4627036eede588553b81333dcf0c30"

  strings:
    $s1 = "0(){return \"Yi\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"Vu\";" ascii
    $s2 = "turn \"TKl\";})(),(function f000(){return \"DIa\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MDb\";})()" ascii
    $s3 = "on f000(){return \"GGn\";})(),(function f000(){return \"UEg\";})(),(function f000(){return \"OUx\";})(),(function f000(){return " ascii
    $s4 = "00(){return \"TKl\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MDb" ascii
    $s5 = ")(),(function f000(){return \"XTn\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"Qz\";})(),(function f000" ascii
    $s6 = "\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"Qz\";})(),(function f0" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}