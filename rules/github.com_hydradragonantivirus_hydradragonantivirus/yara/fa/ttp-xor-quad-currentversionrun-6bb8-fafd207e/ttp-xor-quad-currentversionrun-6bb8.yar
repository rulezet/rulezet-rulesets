rule TTP_XOR_QUAD_CurrentVersionRun_6bb8 {
  strings:
    $key_6bb8 = { 38 d7 [2] 1c d9 [2] 37 f5 [2] 19 d7 [2] 0d cc [2] 02 d6 [2] 1c cb [2] 1e ca [2] 05 cc [2] 19 cb [2] 05 e4 }

  condition:
    any of them
}