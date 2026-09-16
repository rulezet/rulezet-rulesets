rule TTP_XOR_QUAD_CurrentVersionRun_547b {
  strings:
    $key_547b = { 07 14 [2] 23 1a [2] 08 36 [2] 26 14 [2] 32 0f [2] 3d 15 [2] 23 08 [2] 21 09 [2] 3a 0f [2] 26 08 [2] 3a 27 }

  condition:
    any of them
}