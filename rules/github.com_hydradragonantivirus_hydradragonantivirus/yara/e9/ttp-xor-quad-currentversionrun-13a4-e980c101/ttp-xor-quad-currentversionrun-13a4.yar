rule TTP_XOR_QUAD_CurrentVersionRun_13a4 {
  strings:
    $key_13a4 = { 40 cb [2] 64 c5 [2] 4f e9 [2] 61 cb [2] 75 d0 [2] 7a ca [2] 64 d7 [2] 66 d6 [2] 7d d0 [2] 61 d7 [2] 7d f8 }

  condition:
    any of them
}