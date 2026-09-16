rule TTP_XOR_QUAD_CurrentVersionRun_15c0 {
  strings:
    $key_15c0 = { 46 af [2] 62 a1 [2] 49 8d [2] 67 af [2] 73 b4 [2] 7c ae [2] 62 b3 [2] 60 b2 [2] 7b b4 [2] 67 b3 [2] 7b 9c }

  condition:
    any of them
}