rule TTP_XOR_QUAD_CurrentVersionRun_1ea5 {
  strings:
    $key_1ea5 = { 4d ca [2] 69 c4 [2] 42 e8 [2] 6c ca [2] 78 d1 [2] 77 cb [2] 69 d6 [2] 6b d7 [2] 70 d1 [2] 6c d6 [2] 70 f9 }

  condition:
    any of them
}