rule TTP_XOR_QUAD_CurrentVersionRun_e9c7 {
  strings:
    $key_e9c7 = { ba a8 [2] 9e a6 [2] b5 8a [2] 9b a8 [2] 8f b3 [2] 80 a9 [2] 9e b4 [2] 9c b5 [2] 87 b3 [2] 9b b4 [2] 87 9b }

  condition:
    any of them
}