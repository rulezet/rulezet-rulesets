rule TTP_XOR_QUAD_CurrentVersionRun_23a4 {
  strings:
    $key_23a4 = { 70 cb [2] 54 c5 [2] 7f e9 [2] 51 cb [2] 45 d0 [2] 4a ca [2] 54 d7 [2] 56 d6 [2] 4d d0 [2] 51 d7 [2] 4d f8 }

  condition:
    any of them
}