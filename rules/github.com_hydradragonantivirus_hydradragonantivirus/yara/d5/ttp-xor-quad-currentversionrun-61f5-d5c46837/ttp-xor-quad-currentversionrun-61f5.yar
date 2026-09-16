rule TTP_XOR_QUAD_CurrentVersionRun_61f5 {
  strings:
    $key_61f5 = { 32 9a [2] 16 94 [2] 3d b8 [2] 13 9a [2] 07 81 [2] 08 9b [2] 16 86 [2] 14 87 [2] 0f 81 [2] 13 86 [2] 0f a9 }

  condition:
    any of them
}