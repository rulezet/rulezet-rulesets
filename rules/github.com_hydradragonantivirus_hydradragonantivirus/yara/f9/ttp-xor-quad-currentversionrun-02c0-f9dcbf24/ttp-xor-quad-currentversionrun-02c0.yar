rule TTP_XOR_QUAD_CurrentVersionRun_02c0 {
  strings:
    $key_02c0 = { 51 af [2] 75 a1 [2] 5e 8d [2] 70 af [2] 64 b4 [2] 6b ae [2] 75 b3 [2] 77 b2 [2] 6c b4 [2] 70 b3 [2] 6c 9c }

  condition:
    any of them
}