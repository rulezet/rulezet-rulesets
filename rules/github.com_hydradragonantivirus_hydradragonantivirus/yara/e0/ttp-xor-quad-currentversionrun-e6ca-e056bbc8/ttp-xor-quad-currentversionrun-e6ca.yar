rule TTP_XOR_QUAD_CurrentVersionRun_e6ca {
  strings:
    $key_e6ca = { b5 a5 [2] 91 ab [2] ba 87 [2] 94 a5 [2] 80 be [2] 8f a4 [2] 91 b9 [2] 93 b8 [2] 88 be [2] 94 b9 [2] 88 96 }

  condition:
    any of them
}