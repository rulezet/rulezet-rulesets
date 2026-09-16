rule TTP_XOR_QUAD_CurrentVersionRun_45c0 {
  strings:
    $key_45c0 = { 16 af [2] 32 a1 [2] 19 8d [2] 37 af [2] 23 b4 [2] 2c ae [2] 32 b3 [2] 30 b2 [2] 2b b4 [2] 37 b3 [2] 2b 9c }

  condition:
    any of them
}