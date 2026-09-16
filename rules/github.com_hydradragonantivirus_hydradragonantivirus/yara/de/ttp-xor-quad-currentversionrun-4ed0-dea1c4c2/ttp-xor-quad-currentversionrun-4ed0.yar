rule TTP_XOR_QUAD_CurrentVersionRun_4ed0 {
  strings:
    $key_4ed0 = { 1d bf [2] 39 b1 [2] 12 9d [2] 3c bf [2] 28 a4 [2] 27 be [2] 39 a3 [2] 3b a2 [2] 20 a4 [2] 3c a3 [2] 20 8c }

  condition:
    any of them
}