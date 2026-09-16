rule TTP_XOR_QUAD_CurrentVersionRun_f8d5 {
  strings:
    $key_f8d5 = { ab ba [2] 8f b4 [2] a4 98 [2] 8a ba [2] 9e a1 [2] 91 bb [2] 8f a6 [2] 8d a7 [2] 96 a1 [2] 8a a6 [2] 96 89 }

  condition:
    any of them
}