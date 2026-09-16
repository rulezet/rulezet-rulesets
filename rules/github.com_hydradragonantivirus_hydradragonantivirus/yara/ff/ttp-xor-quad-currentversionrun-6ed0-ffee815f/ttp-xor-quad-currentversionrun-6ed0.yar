rule TTP_XOR_QUAD_CurrentVersionRun_6ed0 {
  strings:
    $key_6ed0 = { 3d bf [2] 19 b1 [2] 32 9d [2] 1c bf [2] 08 a4 [2] 07 be [2] 19 a3 [2] 1b a2 [2] 00 a4 [2] 1c a3 [2] 00 8c }

  condition:
    any of them
}