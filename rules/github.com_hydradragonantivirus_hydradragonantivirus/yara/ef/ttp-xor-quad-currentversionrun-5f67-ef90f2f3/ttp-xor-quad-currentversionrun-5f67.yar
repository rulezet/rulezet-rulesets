rule TTP_XOR_QUAD_CurrentVersionRun_5f67 {
  strings:
    $key_5f67 = { 0c 08 [2] 28 06 [2] 03 2a [2] 2d 08 [2] 39 13 [2] 36 09 [2] 28 14 [2] 2a 15 [2] 31 13 [2] 2d 14 [2] 31 3b }

  condition:
    any of them
}