rule TTP_XOR_QUAD_CurrentVersionRun_ddd2 {
  strings:
    $key_ddd2 = { 8e bd [2] aa b3 [2] 81 9f [2] af bd [2] bb a6 [2] b4 bc [2] aa a1 [2] a8 a0 [2] b3 a6 [2] af a1 [2] b3 8e }

  condition:
    any of them
}