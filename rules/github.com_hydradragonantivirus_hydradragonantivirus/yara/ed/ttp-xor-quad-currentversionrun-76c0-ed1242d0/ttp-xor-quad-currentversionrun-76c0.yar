rule TTP_XOR_QUAD_CurrentVersionRun_76c0 {
  strings:
    $key_76c0 = { 25 af [2] 01 a1 [2] 2a 8d [2] 04 af [2] 10 b4 [2] 1f ae [2] 01 b3 [2] 03 b2 [2] 18 b4 [2] 04 b3 [2] 18 9c }

  condition:
    any of them
}