rule TTP_XOR_QUAD_CurrentVersionRun_6165 {
  strings:
    $key_6165 = { 32 0a [2] 16 04 [2] 3d 28 [2] 13 0a [2] 07 11 [2] 08 0b [2] 16 16 [2] 14 17 [2] 0f 11 [2] 13 16 [2] 0f 39 }

  condition:
    any of them
}