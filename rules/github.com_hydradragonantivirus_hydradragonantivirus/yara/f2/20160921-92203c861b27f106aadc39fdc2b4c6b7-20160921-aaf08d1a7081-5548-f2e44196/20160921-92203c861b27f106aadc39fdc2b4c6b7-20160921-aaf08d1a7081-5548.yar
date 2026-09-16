rule _20160921_92203c861b27f106aadc39fdc2b4c6b7_20160921_aaf08d1a7081_5548 {
  meta:
    description = "datamaliciousorder - from files 20160921_92203c861b27f106aadc39fdc2b4c6b7.js, 20160921_aaf08d1a708106f9bd09a913767a56e1.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "307c62eb5d0e72645486ed8ab490a017889f28cb40d74f607fae031e9ef250fb"
    hash2       = "f9cc4d7e90450eb48dcdeb77c2c486f0893efd6ae609a5f1c7bdf6439f61bda7"

  strings:
    $s1 = "00(){return \"Zj\";})(),(function f000(){return \"Ot\";})(),(function f000(){return \"Ot\";})(),(function f000(){return \"MMz\";" ascii
    $s2 = "f000(){return \"Lp\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Qp\";})(),(function f000(){return \"Qp" ascii
    $s3 = "on f000(){return \"RPt\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"DYs\";})(),(function f000(){return " ascii
    $s4 = "tion f000(){return \"RVb\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"DNa\";})(),(function f000(){retur" ascii
    $s5 = "turn \"KXg\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"SEo\";})(),(function f000(){return \"NBs\";})()" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}