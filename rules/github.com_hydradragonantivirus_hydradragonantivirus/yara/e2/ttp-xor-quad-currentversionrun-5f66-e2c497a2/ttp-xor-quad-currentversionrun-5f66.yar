rule TTP_XOR_QUAD_CurrentVersionRun_5f66 {
  strings:
    $key_5f66 = { 0c 09 [2] 28 07 [2] 03 2b [2] 2d 09 [2] 39 12 [2] 36 08 [2] 28 15 [2] 2a 14 [2] 31 12 [2] 2d 15 [2] 31 3a }

  condition:
    any of them
}