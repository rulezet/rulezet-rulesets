rule TTP_XOR_QUAD_CurrentVersionRun_e7ca {
  strings:
    $key_e7ca = { b4 a5 [2] 90 ab [2] bb 87 [2] 95 a5 [2] 81 be [2] 8e a4 [2] 90 b9 [2] 92 b8 [2] 89 be [2] 95 b9 [2] 89 96 }

  condition:
    any of them
}