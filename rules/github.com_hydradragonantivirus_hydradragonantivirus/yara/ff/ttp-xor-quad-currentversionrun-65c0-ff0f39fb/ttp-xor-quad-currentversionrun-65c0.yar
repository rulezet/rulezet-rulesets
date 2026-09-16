rule TTP_XOR_QUAD_CurrentVersionRun_65c0 {
  strings:
    $key_65c0 = { 36 af [2] 12 a1 [2] 39 8d [2] 17 af [2] 03 b4 [2] 0c ae [2] 12 b3 [2] 10 b2 [2] 0b b4 [2] 17 b3 [2] 0b 9c }

  condition:
    any of them
}