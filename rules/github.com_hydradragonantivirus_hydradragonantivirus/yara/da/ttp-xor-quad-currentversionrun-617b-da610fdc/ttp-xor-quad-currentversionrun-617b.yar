rule TTP_XOR_QUAD_CurrentVersionRun_617b {
  strings:
    $key_617b = { 32 14 [2] 16 1a [2] 3d 36 [2] 13 14 [2] 07 0f [2] 08 15 [2] 16 08 [2] 14 09 [2] 0f 0f [2] 13 08 [2] 0f 27 }

  condition:
    any of them
}