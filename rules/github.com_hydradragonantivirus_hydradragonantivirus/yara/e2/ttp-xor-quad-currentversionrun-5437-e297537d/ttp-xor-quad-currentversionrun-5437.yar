rule TTP_XOR_QUAD_CurrentVersionRun_5437 {
  strings:
    $key_5437 = { 07 58 [2] 23 56 [2] 08 7a [2] 26 58 [2] 32 43 [2] 3d 59 [2] 23 44 [2] 21 45 [2] 3a 43 [2] 26 44 [2] 3a 6b }

  condition:
    any of them
}