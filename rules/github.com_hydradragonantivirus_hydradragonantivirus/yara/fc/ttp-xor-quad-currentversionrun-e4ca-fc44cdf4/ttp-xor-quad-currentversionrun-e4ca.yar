rule TTP_XOR_QUAD_CurrentVersionRun_e4ca {
  strings:
    $key_e4ca = { b7 a5 [2] 93 ab [2] b8 87 [2] 96 a5 [2] 82 be [2] 8d a4 [2] 93 b9 [2] 91 b8 [2] 8a be [2] 96 b9 [2] 8a 96 }

  condition:
    any of them
}