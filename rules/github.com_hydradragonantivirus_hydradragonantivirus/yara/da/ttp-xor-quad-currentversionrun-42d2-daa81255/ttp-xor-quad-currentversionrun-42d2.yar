rule TTP_XOR_QUAD_CurrentVersionRun_42d2 {
  strings:
    $key_42d2 = { 11 bd [2] 35 b3 [2] 1e 9f [2] 30 bd [2] 24 a6 [2] 2b bc [2] 35 a1 [2] 37 a0 [2] 2c a6 [2] 30 a1 [2] 2c 8e }

  condition:
    any of them
}