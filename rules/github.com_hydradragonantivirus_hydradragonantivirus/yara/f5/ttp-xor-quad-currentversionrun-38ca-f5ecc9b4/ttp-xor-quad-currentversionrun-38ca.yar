rule TTP_XOR_QUAD_CurrentVersionRun_38ca {
  strings:
    $key_38ca = { 6b a5 [2] 4f ab [2] 64 87 [2] 4a a5 [2] 5e be [2] 51 a4 [2] 4f b9 [2] 4d b8 [2] 56 be [2] 4a b9 [2] 56 96 }

  condition:
    any of them
}