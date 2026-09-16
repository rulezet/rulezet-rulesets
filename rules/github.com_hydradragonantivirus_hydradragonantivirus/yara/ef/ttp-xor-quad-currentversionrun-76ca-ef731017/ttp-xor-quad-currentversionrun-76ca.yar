rule TTP_XOR_QUAD_CurrentVersionRun_76ca {
  strings:
    $key_76ca = { 25 a5 [2] 01 ab [2] 2a 87 [2] 04 a5 [2] 10 be [2] 1f a4 [2] 01 b9 [2] 03 b8 [2] 18 be [2] 04 b9 [2] 18 96 }

  condition:
    any of them
}