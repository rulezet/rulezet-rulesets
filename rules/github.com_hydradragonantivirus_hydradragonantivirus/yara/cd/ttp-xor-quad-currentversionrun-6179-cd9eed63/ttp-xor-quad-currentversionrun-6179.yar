rule TTP_XOR_QUAD_CurrentVersionRun_6179 {
  strings:
    $key_6179 = { 32 16 [2] 16 18 [2] 3d 34 [2] 13 16 [2] 07 0d [2] 08 17 [2] 16 0a [2] 14 0b [2] 0f 0d [2] 13 0a [2] 0f 25 }

  condition:
    any of them
}