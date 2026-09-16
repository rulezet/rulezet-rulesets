rule TTP_XOR_QUAD_CurrentVersionRun_e2c6 {
  strings:
    $key_e2c6 = { b1 a9 [2] 95 a7 [2] be 8b [2] 90 a9 [2] 84 b2 [2] 8b a8 [2] 95 b5 [2] 97 b4 [2] 8c b2 [2] 90 b5 [2] 8c 9a }

  condition:
    any of them
}