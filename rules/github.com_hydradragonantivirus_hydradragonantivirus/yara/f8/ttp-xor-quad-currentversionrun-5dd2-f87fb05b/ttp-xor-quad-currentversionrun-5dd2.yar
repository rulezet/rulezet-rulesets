rule TTP_XOR_QUAD_CurrentVersionRun_5dd2 {
  strings:
    $key_5dd2 = { 0e bd [2] 2a b3 [2] 01 9f [2] 2f bd [2] 3b a6 [2] 34 bc [2] 2a a1 [2] 28 a0 [2] 33 a6 [2] 2f a1 [2] 33 8e }

  condition:
    any of them
}