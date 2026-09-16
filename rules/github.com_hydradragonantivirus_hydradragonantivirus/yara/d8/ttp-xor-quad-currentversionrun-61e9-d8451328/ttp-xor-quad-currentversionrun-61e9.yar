rule TTP_XOR_QUAD_CurrentVersionRun_61e9 {
  strings:
    $key_61e9 = { 32 86 [2] 16 88 [2] 3d a4 [2] 13 86 [2] 07 9d [2] 08 87 [2] 16 9a [2] 14 9b [2] 0f 9d [2] 13 9a [2] 0f b5 }

  condition:
    any of them
}