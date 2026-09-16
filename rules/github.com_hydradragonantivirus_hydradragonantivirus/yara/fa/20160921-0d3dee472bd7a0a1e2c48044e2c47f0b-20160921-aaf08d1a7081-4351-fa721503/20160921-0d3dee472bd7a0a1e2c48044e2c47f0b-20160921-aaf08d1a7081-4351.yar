rule _20160921_0d3dee472bd7a0a1e2c48044e2c47f0b_20160921_aaf08d1a7081_4351 {
  meta:
    description = "datamaliciousorder - from files 20160921_0d3dee472bd7a0a1e2c48044e2c47f0b.js, 20160921_aaf08d1a708106f9bd09a913767a56e1.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9ffda0cd0cd96558031ec49484507d0af3efe8f0ec6fee33e947b4b9515ab24f"
    hash2       = "f9cc4d7e90450eb48dcdeb77c2c486f0893efd6ae609a5f1c7bdf6439f61bda7"

  strings:
    $s1 = " \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"ZIi\";})(),(fu" ascii
    $s2 = ",(function f000(){return \"Tb\";})(),(function f000(){return \"DYx\";})(),(function f000(){return \"GGn\";})(),(function f000(){" ascii
    $s3 = ",(function f000(){return \"Sv\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"TKp\";})(),(function f000(){" ascii
    $s4 = "000(){return \"PTs\";})(),(function f000(){return \"Qa\";})(),(function f000(){return \"DYx\";})(),(function f000(){return \"DIa" ascii
    $s5 = "rn \"GGn\";})(),(function f000(){return \"ZIi\";})(),(function f000(){return \"PTs\";})(),(function f000(){return \"Iq\";})(),(f" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}