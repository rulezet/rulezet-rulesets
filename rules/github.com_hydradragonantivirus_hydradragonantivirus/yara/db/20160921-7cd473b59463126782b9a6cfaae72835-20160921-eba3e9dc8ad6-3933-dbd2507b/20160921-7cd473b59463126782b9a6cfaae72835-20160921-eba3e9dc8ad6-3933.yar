rule _20160921_7cd473b59463126782b9a6cfaae72835_20160921_eba3e9dc8ad6_3933 {
  meta:
    description = "datamaliciousorder - from files 20160921_7cd473b59463126782b9a6cfaae72835.js, 20160921_eba3e9dc8ad614a7e5c422a93cd7b424.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0e3e3663f9696265255bc848bc98ec77487c491ee2a30b3085dbc10087b935c5"
    hash2       = "f0f6c6f4fe3daf7aae3b8d7276adbcc6577a8bf844eeae945023523b63b6cc9a"

  strings:
    $s1 = "eturn \"BQb\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"Yv\";})()," ascii
    $s2 = "Eo\";})(),(function f000(){return \"BQb\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"OUx\";})(),(functio" ascii
    $s3 = "000(){return \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Tb\";})(),(function f000(){return \"SEo" ascii
    $s4 = "unction f000(){return \"GGn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Tb\";})(),(function f000(){ret" ascii
    $s5 = "(function f000(){return \"Wb\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"GGn\";})(),(function f000(){re" ascii
    $s6 = "nction f000(){return \"Tb\";})(),(function f000(){return \"SEo\";})(),(function f000(){return \"BQb\";})(),(function f000(){retu" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}