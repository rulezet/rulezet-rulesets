rule TTP_XOR_QUAD_CurrentVersionRun_65ca {
  strings:
    $key_65ca = { 36 a5 [2] 12 ab [2] 39 87 [2] 17 a5 [2] 03 be [2] 0c a4 [2] 12 b9 [2] 10 b8 [2] 0b be [2] 17 b9 [2] 0b 96 }

  condition:
    any of them
}