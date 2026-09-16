rule TTP_XOR_QUAD_CurrentVersionRun_faca {
  strings:
    $key_faca = { a9 a5 [2] 8d ab [2] a6 87 [2] 88 a5 [2] 9c be [2] 93 a4 [2] 8d b9 [2] 8f b8 [2] 94 be [2] 88 b9 [2] 94 96 }

  condition:
    any of them
}