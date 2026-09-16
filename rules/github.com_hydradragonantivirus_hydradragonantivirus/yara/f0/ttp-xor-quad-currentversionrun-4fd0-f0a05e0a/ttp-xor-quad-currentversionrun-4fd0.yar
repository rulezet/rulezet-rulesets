rule TTP_XOR_QUAD_CurrentVersionRun_4fd0 {
  strings:
    $key_4fd0 = { 1c bf [2] 38 b1 [2] 13 9d [2] 3d bf [2] 29 a4 [2] 26 be [2] 38 a3 [2] 3a a2 [2] 21 a4 [2] 3d a3 [2] 21 8c }

  condition:
    any of them
}