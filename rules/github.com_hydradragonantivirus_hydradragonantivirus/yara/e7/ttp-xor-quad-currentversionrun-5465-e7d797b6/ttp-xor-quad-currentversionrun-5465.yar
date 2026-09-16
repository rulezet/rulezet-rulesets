rule TTP_XOR_QUAD_CurrentVersionRun_5465 {
  strings:
    $key_5465 = { 07 0a [2] 23 04 [2] 08 28 [2] 26 0a [2] 32 11 [2] 3d 0b [2] 23 16 [2] 21 17 [2] 3a 11 [2] 26 16 [2] 3a 39 }

  condition:
    any of them
}