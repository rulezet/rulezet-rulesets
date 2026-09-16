rule TTP_XOR_QUAD_CurrentVersionRun_4ae9 {
  strings:
    $key_4ae9 = { 19 86 [2] 3d 88 [2] 16 a4 [2] 38 86 [2] 2c 9d [2] 23 87 [2] 3d 9a [2] 3f 9b [2] 24 9d [2] 38 9a [2] 24 b5 }

  condition:
    any of them
}