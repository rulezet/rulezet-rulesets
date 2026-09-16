rule TTP_XOR_QUAD_CurrentVersionRun_fcd2 {
  strings:
    $key_fcd2 = { af bd [2] 8b b3 [2] a0 9f [2] 8e bd [2] 9a a6 [2] 95 bc [2] 8b a1 [2] 89 a0 [2] 92 a6 [2] 8e a1 [2] 92 8e }

  condition:
    any of them
}