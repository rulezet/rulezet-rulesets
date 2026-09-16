rule TTP_XOR_QUAD_CurrentVersionRun_e3ca {
  strings:
    $key_e3ca = { b0 a5 [2] 94 ab [2] bf 87 [2] 91 a5 [2] 85 be [2] 8a a4 [2] 94 b9 [2] 96 b8 [2] 8d be [2] 91 b9 [2] 8d 96 }

  condition:
    any of them
}