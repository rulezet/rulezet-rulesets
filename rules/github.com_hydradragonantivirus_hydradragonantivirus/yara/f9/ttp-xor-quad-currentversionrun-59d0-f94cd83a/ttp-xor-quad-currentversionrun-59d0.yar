rule TTP_XOR_QUAD_CurrentVersionRun_59d0 {
  strings:
    $key_59d0 = { 0a bf [2] 2e b1 [2] 05 9d [2] 2b bf [2] 3f a4 [2] 30 be [2] 2e a3 [2] 2c a2 [2] 37 a4 [2] 2b a3 [2] 37 8c }

  condition:
    any of them
}