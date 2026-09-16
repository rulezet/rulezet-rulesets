rule TTP_XOR_QUAD_CurrentVersionRun_f4c0 {
  strings:
    $key_f4c0 = { a7 af [2] 83 a1 [2] a8 8d [2] 86 af [2] 92 b4 [2] 9d ae [2] 83 b3 [2] 81 b2 [2] 9a b4 [2] 86 b3 [2] 9a 9c }

  condition:
    any of them
}