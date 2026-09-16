rule TTP_XOR_QUAD_CurrentVersionRun_e2c0 {
  strings:
    $key_e2c0 = { b1 af [2] 95 a1 [2] be 8d [2] 90 af [2] 84 b4 [2] 8b ae [2] 95 b3 [2] 97 b2 [2] 8c b4 [2] 90 b3 [2] 8c 9c }

  condition:
    any of them
}