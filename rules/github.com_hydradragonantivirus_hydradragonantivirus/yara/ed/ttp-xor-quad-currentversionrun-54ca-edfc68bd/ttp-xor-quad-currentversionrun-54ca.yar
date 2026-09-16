rule TTP_XOR_QUAD_CurrentVersionRun_54ca {
  strings:
    $key_54ca = { 07 a5 [2] 23 ab [2] 08 87 [2] 26 a5 [2] 32 be [2] 3d a4 [2] 23 b9 [2] 21 b8 [2] 3a be [2] 26 b9 [2] 3a 96 }

  condition:
    any of them
}