rule TTP_XOR_QUAD_CurrentVersionRun_2f74 {
  strings:
    $key_2f74 = { 7c 1b [2] 58 15 [2] 73 39 [2] 5d 1b [2] 49 00 [2] 46 1a [2] 58 07 [2] 5a 06 [2] 41 00 [2] 5d 07 [2] 41 28 }

  condition:
    any of them
}