rule TTP_XOR_QUAD_CurrentVersionRun_ddb7 {
  strings:
    $key_ddb7 = { 8e d8 [2] aa d6 [2] 81 fa [2] af d8 [2] bb c3 [2] b4 d9 [2] aa c4 [2] a8 c5 [2] b3 c3 [2] af c4 [2] b3 eb }

  condition:
    any of them
}