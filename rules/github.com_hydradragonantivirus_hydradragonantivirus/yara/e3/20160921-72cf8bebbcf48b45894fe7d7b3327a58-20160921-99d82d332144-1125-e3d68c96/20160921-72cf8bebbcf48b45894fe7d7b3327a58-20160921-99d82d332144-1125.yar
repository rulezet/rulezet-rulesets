rule _20160921_72cf8bebbcf48b45894fe7d7b3327a58_20160921_99d82d332144_1125 {
  meta:
    description = "datamaliciousorder - from files 20160921_72cf8bebbcf48b45894fe7d7b3327a58.js, 20160921_99d82d33214407e421e255b85f02daae.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "004799df77a97e1e1816f6a4a1acf9bec5dfd13ae07613832796a6c9ef0cc578"
    hash2       = "9f95318ee468d352a07628edd848ed3cb97379fab3e416b20eeb631ea656c3a9"

  strings:
    $s1  = ";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"IAa\";})(),(function f000(){return \"Nv\";})(),(function f0" ascii
    $s2  = "){return \"RLk\";})(),(function f000(){return \"Mc\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MDb\";}" ascii
    $s3  = "f000(){return \"Lo\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"Vu" ascii
    $s4  = "{return \"ZGq\";})(),(function f000(){return \"PTi\";})(),(function f000(){return \"RVb\";})(),(function f000(){return \"GGn\";}" ascii
    $s5  = "n f000(){return \"WIj\";})(),(function f000(){return \"EZu\";})(),(function f000(){return \"MJq\";})(),(function f000(){return " ascii
    $s6  = "(),(function f000(){return \"Mt\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"TRc\";})(),(function f000()" ascii
    $s7  = "ion f000(){return \"OUx\";})(),(function f000(){return \"SEo\";})(),(function f000(){return \"Nv\";})(),(function f000(){return " ascii
    $s8  = "ction f000(){return \"GGn\";})(),(function f000(){return \"MBb\";})(),(function f000(){return \"Mt\";})(),(function f000(){retur" ascii
    $s9  = "(){return \"PTs\";})(),(function f000(){return \"Uo\";})(),(function f000(){return \"Wy\";})(),(function f000(){return \"Yi\";})" ascii
    $s10 = "\";})(),(function f000(){return \"ZIi\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"WIj\";})(),(function" ascii
    $s11 = "0(){return \"ZGq\";})(),(function f000(){return \"Nx\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"GGn\"" ascii
    $s12 = "rn \"Sj\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Ut\";})(),(fu" ascii
    $s13 = "{return \"Vu\";})(),(function f000(){return \"BQb\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"Zj\";})()" ascii
    $s14 = "nction f000(){return \"DNa\";})(),(function f000(){return \"Sj\";})(),(function f000(){return \"Qj\";})(),(function f000(){retur" ascii
    $s15 = "turn \"Qz\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"RLk\";})(),(function f000(){return \"Mc\";})(),(" ascii
    $s16 = "),(function f000(){return \"OUx\";})(),(function f000(){return \"IAa\";})(),(function f000(){return \"TKp\";})(),(function f000(" ascii
    $s17 = "(){return \"Qz\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"BMj\";})(),(function f000(){return \"Yz\";}" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}