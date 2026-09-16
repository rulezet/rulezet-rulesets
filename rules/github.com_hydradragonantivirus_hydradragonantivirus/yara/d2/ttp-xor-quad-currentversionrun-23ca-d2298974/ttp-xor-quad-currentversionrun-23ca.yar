rule TTP_XOR_QUAD_CurrentVersionRun_23ca {
  strings:
    $key_23ca = { 70 a5 [2] 54 ab [2] 7f 87 [2] 51 a5 [2] 45 be [2] 4a a4 [2] 54 b9 [2] 56 b8 [2] 4d be [2] 51 b9 [2] 4d 96 }

  condition:
    any of them
}