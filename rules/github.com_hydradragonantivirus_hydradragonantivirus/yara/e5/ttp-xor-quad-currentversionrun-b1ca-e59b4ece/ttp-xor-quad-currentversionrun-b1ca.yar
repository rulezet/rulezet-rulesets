rule TTP_XOR_QUAD_CurrentVersionRun_b1ca {
  strings:
    $key_b1ca = { e2 a5 [2] c6 ab [2] ed 87 [2] c3 a5 [2] d7 be [2] d8 a4 [2] c6 b9 [2] c4 b8 [2] df be [2] c3 b9 [2] df 96 }

  condition:
    any of them
}