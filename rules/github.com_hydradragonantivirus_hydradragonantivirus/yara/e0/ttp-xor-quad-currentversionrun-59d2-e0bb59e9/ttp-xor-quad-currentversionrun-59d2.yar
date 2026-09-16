rule TTP_XOR_QUAD_CurrentVersionRun_59d2 {
  strings:
    $key_59d2 = { 0a bd [2] 2e b3 [2] 05 9f [2] 2b bd [2] 3f a6 [2] 30 bc [2] 2e a1 [2] 2c a0 [2] 37 a6 [2] 2b a1 [2] 37 8e }

  condition:
    any of them
}