rule TTP_XOR_QUAD_CurrentVersionRun_59d1 {
  strings:
    $key_59d1 = { 0a be [2] 2e b0 [2] 05 9c [2] 2b be [2] 3f a5 [2] 30 bf [2] 2e a2 [2] 2c a3 [2] 37 a5 [2] 2b a2 [2] 37 8d }

  condition:
    any of them
}