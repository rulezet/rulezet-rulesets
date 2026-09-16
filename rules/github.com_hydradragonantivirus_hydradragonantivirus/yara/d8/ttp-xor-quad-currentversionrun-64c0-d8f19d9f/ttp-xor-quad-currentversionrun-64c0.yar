rule TTP_XOR_QUAD_CurrentVersionRun_64c0 {
  strings:
    $key_64c0 = { 37 af [2] 13 a1 [2] 38 8d [2] 16 af [2] 02 b4 [2] 0d ae [2] 13 b3 [2] 11 b2 [2] 0a b4 [2] 16 b3 [2] 0a 9c }

  condition:
    any of them
}