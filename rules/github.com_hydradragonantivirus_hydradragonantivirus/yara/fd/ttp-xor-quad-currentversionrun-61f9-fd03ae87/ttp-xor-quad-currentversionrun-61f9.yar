rule TTP_XOR_QUAD_CurrentVersionRun_61f9 {
  strings:
    $key_61f9 = { 32 96 [2] 16 98 [2] 3d b4 [2] 13 96 [2] 07 8d [2] 08 97 [2] 16 8a [2] 14 8b [2] 0f 8d [2] 13 8a [2] 0f a5 }

  condition:
    any of them
}