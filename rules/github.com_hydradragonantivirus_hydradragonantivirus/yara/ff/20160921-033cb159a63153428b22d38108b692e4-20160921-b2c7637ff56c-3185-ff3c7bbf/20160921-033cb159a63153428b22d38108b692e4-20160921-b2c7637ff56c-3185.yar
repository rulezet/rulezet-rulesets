rule _20160921_033cb159a63153428b22d38108b692e4_20160921_b2c7637ff56c_3185 {
  meta:
    description = "datamaliciousorder - from files 20160921_033cb159a63153428b22d38108b692e4.js, 20160921_b2c7637ff56cbf278f1a457ae1833df9.js, 20160922_edfdc00dbdbb7dfd43478925b51e4a4b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d370303fc83ddc3470e00cb54841641f9f338c2f025096e84d40782778041a8b"
    hash2       = "a19789bb6f28d27bc82c039f4db69fb5cc4c189a7a47cddfffcdc6eace37a408"
    hash3       = "8672bbf21d7f10931a3f6328634b8b4e6160470a85d97fb93d56cb5eedb10599"

  strings:
    $s1 = "(),(function f000(){return \"ZIi\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"WIj\";})(),(function f000" ascii
    $s2 = "000(){return \"ZFe\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"TKl" ascii
    $s3 = " f000(){return \"GGn\";})(),(function f000(){return \"BMj\";})(),(function f000(){return \"MBb\";})(),(function f000(){return \"" ascii
    $s4 = "(),(function f000(){return \"BMj\";})(),(function f000(){return \"IPu\";})(),(function f000(){return \"XTn\";})(),(function f000" ascii
    $s5 = "0(){return \"PTs\";})(),(function f000(){return \"Iq\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"Ml\";}" ascii
    $s6 = "(function f000(){return \"Nv\";})(),(function f000(){return \"DNa\";})(),(function f000(){return \"UEg\";})(),(function f000(){r" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}