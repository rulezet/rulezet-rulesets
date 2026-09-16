rule TTP_XOR_QUAD_CurrentVersionRun_03a4 {
  strings:
    $key_03a4 = { 50 cb [2] 74 c5 [2] 5f e9 [2] 71 cb [2] 65 d0 [2] 6a ca [2] 74 d7 [2] 76 d6 [2] 6d d0 [2] 71 d7 [2] 6d f8 }

  condition:
    any of them
}