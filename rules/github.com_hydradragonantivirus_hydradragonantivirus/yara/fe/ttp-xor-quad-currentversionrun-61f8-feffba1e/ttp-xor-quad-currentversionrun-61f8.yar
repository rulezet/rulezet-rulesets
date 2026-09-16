rule TTP_XOR_QUAD_CurrentVersionRun_61f8 {
  strings:
    $key_61f8 = { 32 97 [2] 16 99 [2] 3d b5 [2] 13 97 [2] 07 8c [2] 08 96 [2] 16 8b [2] 14 8a [2] 0f 8c [2] 13 8b [2] 0f a4 }

  condition:
    any of them
}