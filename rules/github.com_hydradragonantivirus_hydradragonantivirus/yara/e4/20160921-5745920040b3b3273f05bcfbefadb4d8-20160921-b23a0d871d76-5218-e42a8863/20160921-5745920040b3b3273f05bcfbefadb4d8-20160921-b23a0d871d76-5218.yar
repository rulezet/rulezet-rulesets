rule _20160921_5745920040b3b3273f05bcfbefadb4d8_20160921_b23a0d871d76_5218 {
  meta:
    description = "datamaliciousorder - from files 20160921_5745920040b3b3273f05bcfbefadb4d8.js, 20160921_b23a0d871d76c64a3c71f0b0f52faaa8.js, 20160921_ce3c0604d52e9dc9119cefedfee34385.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "86b6dab46ebbd6ed243e73b97070b8a7b74178533a419d7a22c3842a74574534"
    hash2       = "02969139df11550b994530c0bcbc6d946b6e49105015e9475f5de3942d78e5a1"
    hash3       = "27a20a400d7aa13737d230acf36a2170494c7da92e72552775d19562ba331fdc"

  strings:
    $s1 = "n fuck(){return \"YAv\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return " ascii
    $s2 = "(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"Np\";})(),(function fuck()" ascii
    $s3 = ",(function fuck(){return \"Fv\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){" ascii
    $s4 = "return \"TTs\";})(),(function fuck(){return \"CCb\";})(),(function fuck(){return \"IOs\";})(),(function fuck(){return \"UOe\";})" ascii
    $s5 = " \"Vb\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"Hs\";})(),(funct" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}