rule TTP_XOR_QUAD_CurrentVersionRun_67ca {
  strings:
    $key_67ca = { 34 a5 [2] 10 ab [2] 3b 87 [2] 15 a5 [2] 01 be [2] 0e a4 [2] 10 b9 [2] 12 b8 [2] 09 be [2] 15 b9 [2] 09 96 }

  condition:
    any of them
}