rule TTP_XOR_QUAD_CurrentVersionRun_74a4 {
  strings:
    $key_74a4 = { 27 cb [2] 03 c5 [2] 28 e9 [2] 06 cb [2] 12 d0 [2] 1d ca [2] 03 d7 [2] 01 d6 [2] 1a d0 [2] 06 d7 [2] 1a f8 }

  condition:
    any of them
}