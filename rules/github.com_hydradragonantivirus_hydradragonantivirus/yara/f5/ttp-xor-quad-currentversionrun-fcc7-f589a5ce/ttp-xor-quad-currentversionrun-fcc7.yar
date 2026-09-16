rule TTP_XOR_QUAD_CurrentVersionRun_fcc7 {
  strings:
    $key_fcc7 = { af a8 [2] 8b a6 [2] a0 8a [2] 8e a8 [2] 9a b3 [2] 95 a9 [2] 8b b4 [2] 89 b5 [2] 92 b3 [2] 8e b4 [2] 92 9b }

  condition:
    any of them
}