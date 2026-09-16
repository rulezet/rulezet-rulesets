rule TTP_XOR_QUAD_CurrentVersionRun_c3a4 {
  strings:
    $key_c3a4 = { 90 cb [2] b4 c5 [2] 9f e9 [2] b1 cb [2] a5 d0 [2] aa ca [2] b4 d7 [2] b6 d6 [2] ad d0 [2] b1 d7 [2] ad f8 }

  condition:
    any of them
}