rule TTP_XOR_QUAD_CurrentVersionRun_0bb8 {
  strings:
    $key_0bb8 = { 58 d7 [2] 7c d9 [2] 57 f5 [2] 79 d7 [2] 6d cc [2] 62 d6 [2] 7c cb [2] 7e ca [2] 65 cc [2] 79 cb [2] 65 e4 }

  condition:
    any of them
}