rule TTP_XOR_QUAD_CurrentVersionRun_05c0 {
  strings:
    $key_05c0 = { 56 af [2] 72 a1 [2] 59 8d [2] 77 af [2] 63 b4 [2] 6c ae [2] 72 b3 [2] 70 b2 [2] 6b b4 [2] 77 b3 [2] 6b 9c }

  condition:
    any of them
}