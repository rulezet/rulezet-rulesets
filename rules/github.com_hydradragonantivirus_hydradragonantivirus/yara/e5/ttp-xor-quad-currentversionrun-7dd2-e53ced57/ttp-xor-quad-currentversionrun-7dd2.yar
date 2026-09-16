rule TTP_XOR_QUAD_CurrentVersionRun_7dd2 {
  strings:
    $key_7dd2 = { 2e bd [2] 0a b3 [2] 21 9f [2] 0f bd [2] 1b a6 [2] 14 bc [2] 0a a1 [2] 08 a0 [2] 13 a6 [2] 0f a1 [2] 13 8e }

  condition:
    any of them
}