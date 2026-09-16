rule _20160921_aa105be6eeb7f536b3fae098f4cc14ed_20160921_aaf08d1a7081_3110 {
  meta:
    description = "datamaliciousorder - from files 20160921_aa105be6eeb7f536b3fae098f4cc14ed.js, 20160921_aaf08d1a708106f9bd09a913767a56e1.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "df7bae330cc77ba04437c13d3843c951b5c3db558d70c922c4f339dfdc29abbd"
    hash2       = "f9cc4d7e90450eb48dcdeb77c2c486f0893efd6ae609a5f1c7bdf6439f61bda7"

  strings:
    $s1 = "00(){return \"Lp\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"Nv\";" ascii
    $s2 = ";})(),(function f000(){return \"YTp\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"Vu\";})(),(function f0" ascii
    $s3 = "n \"SGs\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"Sq\";})(),(fun" ascii
    $s4 = "unction f000(){return \"XTn\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"Qz\";})(),(function f000(){ret" ascii
    $s5 = "),(function f000(){return \"MDb\";})(),(function f000(){return \"Sv\";})(),(function f000(){return \"PTs\";})(),(function f000()" ascii
    $s6 = "on f000(){return \"Do\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"" ascii
    $s7 = "eturn \"YTp\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"HJm\";})(),(function f000(){return \"Mt\";})()" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}