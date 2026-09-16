rule TTP_XOR_QUAD_CurrentVersionRun_30a5 {
  strings:
    $key_30a5 = { 63 ca [2] 47 c4 [2] 6c e8 [2] 42 ca [2] 56 d1 [2] 59 cb [2] 47 d6 [2] 45 d7 [2] 5e d1 [2] 42 d6 [2] 5e f9 }

  condition:
    any of them
}