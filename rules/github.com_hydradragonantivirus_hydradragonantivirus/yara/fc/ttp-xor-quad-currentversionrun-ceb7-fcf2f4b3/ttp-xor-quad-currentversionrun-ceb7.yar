rule TTP_XOR_QUAD_CurrentVersionRun_ceb7 {
  strings:
    $key_ceb7 = { 9d d8 [2] b9 d6 [2] 92 fa [2] bc d8 [2] a8 c3 [2] a7 d9 [2] b9 c4 [2] bb c5 [2] a0 c3 [2] bc c4 [2] a0 eb }

  condition:
    any of them
}