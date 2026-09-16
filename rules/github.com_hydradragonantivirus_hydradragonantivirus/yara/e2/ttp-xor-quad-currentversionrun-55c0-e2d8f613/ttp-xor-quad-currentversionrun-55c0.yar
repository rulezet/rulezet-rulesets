rule TTP_XOR_QUAD_CurrentVersionRun_55c0 {
  strings:
    $key_55c0 = { 06 af [2] 22 a1 [2] 09 8d [2] 27 af [2] 33 b4 [2] 3c ae [2] 22 b3 [2] 20 b2 [2] 3b b4 [2] 27 b3 [2] 3b 9c }

  condition:
    any of them
}