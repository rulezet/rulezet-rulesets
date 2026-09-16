rule TTP_XOR_QUAD_CurrentVersionRun_e9d5 {
  strings:
    $key_e9d5 = { ba ba [2] 9e b4 [2] b5 98 [2] 9b ba [2] 8f a1 [2] 80 bb [2] 9e a6 [2] 9c a7 [2] 87 a1 [2] 9b a6 [2] 87 89 }

  condition:
    any of them
}