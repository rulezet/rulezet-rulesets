rule TTP_XOR_QUAD_CurrentVersionRun_22ca {
  strings:
    $key_22ca = { 71 a5 [2] 55 ab [2] 7e 87 [2] 50 a5 [2] 44 be [2] 4b a4 [2] 55 b9 [2] 57 b8 [2] 4c be [2] 50 b9 [2] 4c 96 }

  condition:
    any of them
}