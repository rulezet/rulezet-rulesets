rule _20160921_25c11e2eab44b5e0380e0bd805a72790_20160921_b062b54e33ac_2817 {
  meta:
    description = "datamaliciousorder - from files 20160921_25c11e2eab44b5e0380e0bd805a72790.js, 20160921_b062b54e33ac394b0c1a389b161f5cb6.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "912d9aec3079fb6a2e4f83d3826286707a52a653de6ec6eede9711d5b416a790"
    hash2       = "5d0516ba7ba35ed307fd316146755f07fe542904a37fc2e0bb6a28a59cb06139"

  strings:
    $s1 = "(function f000(){return \"PTs\";})(),(function f000(){return \"YTp\";})(),(function f000(){return \"Qj\";})(),(function f000(){r" ascii
    $s2 = "00(){return \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MBb\";})(),(function f000(){return \"IPu" ascii
    $s3 = "(){return \"DIa\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Rh\";}" ascii
    $s4 = " \"GGn\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"SEo\";})(),(function f000(){return \"BMj\";})(),(fun" ascii
    $s5 = "rn \"QDg\";})(),(function f000(){return \"Nv\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"UEg\";})(),(fu" ascii
    $s6 = "function f000(){return \"HJm\";})(),(function f000(){return \"YTp\";})(),(function f000(){return \"XTn\";})(),(function f000(){r" ascii
    $s7 = "\"GGn\";})(),(function f000(){return \"ZIi\";})(),(function f000(){return \"DYs\";})(),(function f000(){return \"YTp\";})(),(fun" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}